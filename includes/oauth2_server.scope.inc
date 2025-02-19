<?php

/**
 * Entity class representing the oauth2_server_scope entity type.
 */
class OAuth2ServerScope extends Entity {

  /**
   * The machine name of the parent server.
   *
   * @var string
   */
  public $server;

  /**
   * The machine name of the scope.
   *
   * @var string
   */
  public $name;

  /**
   * The description used to describe the scope on the authorization form.
   *
   * @var string
   */
  public $description;

  public function __construct($values = array()) {
    parent::__construct($values, 'oauth2_server_scope');
  }

  public function id()
  {
    // TODO: Implement id() method.
  }

  public function entityType()
  {
    // TODO: Implement entityType() method.
  }

  public function label()
  {
    // TODO: Implement label() method.
  }

  public function uri()
  {
    // TODO: Implement uri() method.
  }
}
