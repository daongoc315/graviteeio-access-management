/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.am.repository.jdbc.management.api;

import io.gravitee.am.common.utils.RandomString;
import io.gravitee.am.model.Form;
import io.gravitee.am.model.ReferenceType;
import io.gravitee.am.repository.jdbc.management.AbstractJdbcRepository;
import io.gravitee.am.repository.jdbc.management.api.model.JdbcForm;
import io.gravitee.am.repository.jdbc.management.api.spring.SpringFormRepository;
import io.gravitee.am.repository.management.api.FormRepository;
import io.reactivex.Completable;
import io.reactivex.Flowable;
import io.reactivex.Maybe;
import io.reactivex.Single;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Mono;

import java.util.List;

import static reactor.adapter.rxjava.RxJava2Adapter.monoToSingle;

/**
 * @author Eric LELEU (eric.leleu at graviteesource.com)
 * @author GraviteeSource Team
 */
@Repository
public class JdbcFormRepository extends AbstractJdbcRepository implements FormRepository {

    @Autowired
    private SpringFormRepository formRepository;

    protected Form toEntity(JdbcForm entity) {
        return mapper.map(entity, Form.class);
    }

    protected JdbcForm toJdbcEntity(Form entity) {
        return mapper.map(entity, JdbcForm.class);
    }

    @Override
    public Single<List<Form>> findAll(ReferenceType referenceType, String referenceId) {
        LOGGER.debug("findAll({}, {})", referenceType, referenceId);
        return formRepository.findAll(referenceType.name(), referenceId)
                .map(this::toEntity)
                .toList()
                .doOnError(error -> LOGGER.error("Unable to retrieve Forms with referenceId '{}' and referenceType '{}'", referenceId, referenceType, error));
    }

    @Override
    public Flowable<Form> findAll(ReferenceType referenceType) {LOGGER.debug("findAll({})", referenceType);
        return formRepository.findAll(referenceType.name())
                .map(this::toEntity)
                .doOnError(error -> LOGGER.error("Unable to retrieve Forms with referenceType '{}'", referenceType, error));
    }

    @Override
    public Single<List<Form>> findByDomain(String domain) {
        LOGGER.debug("findByDomain({})", domain);
        return this.findAll(ReferenceType.DOMAIN, domain);
    }

    @Override
    public Single<List<Form>> findByClient(ReferenceType referenceType, String referenceId, String client) {
        LOGGER.debug("findByClient({}, {}, {})", referenceType, referenceId, client);
        return formRepository.findByClient(referenceType.name(), referenceId, client)
                .map(this::toEntity)
                .toList()
                .doOnError(error -> LOGGER.error("Unable to retrieve Forms with referenceId '{}', referenceType '{}' and client '{}'",
                        referenceId, referenceType, client, error));
    }

    @Override
    public Maybe<Form> findByTemplate(ReferenceType referenceType, String referenceId, String template) {
        LOGGER.debug("findByTemplate({}, {}, {})", referenceType, referenceId, template);
        return formRepository.findByTemplate(referenceType.name(), referenceId, template)
                .map(this::toEntity)
                .doOnError(error -> LOGGER.error("Unable to retrieve Form with referenceId '{}', referenceType '{}' and template '{}'",
                        referenceId, referenceType, template, error));
    }

    @Override
    public Maybe<Form> findByClientAndTemplate(ReferenceType referenceType, String referenceId, String client, String template) {
        LOGGER.debug("findByClientAndTemplate({}, {}, {}, {})", referenceType, referenceId, client, template);
        return formRepository.findByClientAndTemplate(referenceType.name(), referenceId, client, template)
                .map(this::toEntity)
                .doOnError(error -> LOGGER.error("Unable to retrieve Form with referenceId '{}', referenceType '{}', client '{}' and template '{}'",
                        referenceId, referenceType, client, template, error));
    }

    @Override
    public Maybe<Form> findById(ReferenceType referenceType, String referenceId, String id) {
        LOGGER.debug("findById({}, {}, {})", referenceType, referenceId, id);
        return formRepository.findById(referenceType.name(), referenceId, id)
                .map(this::toEntity)
                .doOnError(error -> LOGGER.error("Unable to retrieve Form with referenceId '{}', referenceType '{}' and id '{}'",
                        referenceId, referenceType, id, error));
    }

    @Override
    public Maybe<Form> findById(String id) {
        LOGGER.debug("findById({})", id);
        return formRepository.findById(id)
                .map(this::toEntity)
                .doOnError(error -> LOGGER.error("Unable to retrieve Form with id '{}'", id, error));
    }

    @Override
    public Single<Form> create(Form item) {
        item.setId(item.getId() == null ? RandomString.generate() : item.getId());
        LOGGER.debug("create forms with id {}", item.getId());

        Mono<Integer> action = dbClient.insert()
                .into(JdbcForm.class)
                .using(toJdbcEntity(item))
                .fetch().rowsUpdated();

        return monoToSingle(action).flatMap((i) -> this.findById(item.getId()).toSingle())
                .doOnError((error) -> LOGGER.error("unable to create forms with id {}", item.getId(), error));
    }

    @Override
    public Single<Form> update(Form item) {
        LOGGER.debug("update forms with id {}", item.getId());
        return this.formRepository.save(toJdbcEntity(item))
                .map(this::toEntity)
                .doOnError((error) -> LOGGER.error("unable to update forms with id {}", item.getId(), error));
    }

    @Override
    public Completable delete(String id) {
        LOGGER.debug("delete({})", id);
        return formRepository.deleteById(id)
                .doOnError(error -> LOGGER.error("Unable to delete Form with id '{}'", id, error));
    }
}
