Return-Path: <kasan-dev+bncBCC2JRVCV4NRBOH7RXCQMGQES6MLKPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id EA534B2B1B2
	for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 21:32:09 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45a1b0d0feasf27903075e9.2
        for <lists+kasan-dev@lfdr.de>; Mon, 18 Aug 2025 12:32:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755545529; cv=pass;
        d=google.com; s=arc-20240605;
        b=G563r27mCvfbZ/0WXhSnmtgucFqgdXo0EZNuvbkSDXrR2GEldA+uTqFCj+AclVTjOX
         WrPM2p/pNWoCzqIuPR7lUMHM9/mDLITj5Rz8bqK8XX5Qpnftwo2KdECdmP6NkR/zUfEG
         atgEYrszOqUAX+AxHtALk+/shmvoTMo74Qb7pbERtAsgZlL6vblJzi90FQyFbwRdJJNe
         zYCz9wPtukK0WTBt9PNOvGTomIjRvRbRoTBLnC/dVZfE2qt0HucxpNNeKlyu9QCyxa6l
         EqH5i/5T76YEdBHCEloJmnAPBnMFt/5OcGsfqMk71iM8QiUh3uGUJP8eUcKxs588lOpr
         KLxQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id:cc:date
         :in-reply-to:from:subject:mime-version:sender:dkim-signature;
        bh=ypV5ljhmbNcp+cBTZYVnUZTc0q1Ug7zJX0jHzrpHhHY=;
        fh=KpGmPrnoxkeai1BY+cb2U9R9jYtsT51EFefDtqht3wI=;
        b=PK8zR1m8joomiBNGoZju++htt7wyGeSnlI/Aemim4Ucm3QfQVvbyVtzazBdLfpsNsj
         6OjurPfkNTE15yHfjwJ3CuODPkEgdIT52INFKa4cg3ow4uL22C7ant09Mwz/WlrnHbCY
         wjRaUsk7sWOhd0XMQH8+qf1HgrrJwU2B7vLGjJhi3oRasJ41fvBz7IEi3jzxxd4IMiP/
         Ju4YNO9xNhtIU2bfqJv4NY7X/IC08qs3Y60/taTkkRXaU4GNvYHW2xWaD+hx0MP16O9p
         SUFVJadZV3Cw566N9H6xWbTNcNaxBhLz2SHCqr7dhiy7pGzOb0MCdP2tpzHWeAGtXBwJ
         llUQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=A587SMQv;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755545529; x=1756150329; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:to:references:message-id:cc:date:in-reply-to:from
         :subject:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ypV5ljhmbNcp+cBTZYVnUZTc0q1Ug7zJX0jHzrpHhHY=;
        b=I5madQaZg0z0m7O9y1STwy2nKwbiigcGWa7wS0BJ+3FNxi94Ej/I6LD0XxLWnHVoz2
         bEDWWBsaeLPDeoBPhR2MI6aZnPPd1Xt26b/5g5BedwRh1D3fXD5B2kKX7NtzOROzqHZy
         YB3MHo6R79DdA2NeY1wBhTKEwNjaVxXQYFP62kll7HxVqj1U7vTDKMJGM4r2/ROx3NOt
         fbJDxUyBi3aBYF5etHTF7KlKDgKihILmUhqf4M6IMfCtsGhVce+ZOBssfgpaN14keWsO
         lqcY2WmmamDWWIgFyyUZUHofXMHmToMYWaL0WO8sYjt0jcz/k+VWJIwp7dbS4YBi1HnP
         uRGA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755545529; x=1756150329;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:to:references
         :message-id:cc:date:in-reply-to:from:subject:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=ypV5ljhmbNcp+cBTZYVnUZTc0q1Ug7zJX0jHzrpHhHY=;
        b=NXFZkNDd1spQ3zseF0bkQPa2I9CAaCHL9Qx/SFCliYwxFzxVel/njHB25yB8s/AgBh
         GJQEzMy9HHwF6N2lytKmFVYghSeSZiE3/jWtKSKjFZPlhLtToYoArMNyRB6vHUY/ChWx
         Lvep5zllfkFZAQh5LdCNXa/9y8JaSBOb/b/ZzYCfDHT19CGbv61tGyyud44EjUo4TUn7
         W0g58pXopW43Kqv1OaaaVr2ebvcrodSGMh4as0PkQIgMK84ylHOkBbvdY9Kf7nUu6X38
         bJr0xawr9N0hInCCAmfc3VswnHu6mkaHzxrPn3lL4zg3ZBr7AemyoECQ8dOWV2c9fqSZ
         hPsA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUAloRYFI8sfFbP89TIZCoAx5Uir+Llh+GwNFFQ8z67jLHLmsjtzPWlxU+NYREI1ThYA+GzFA==@lfdr.de
X-Gm-Message-State: AOJu0YxVkPQSPTCFv/mgbI7jq5nAu3tH6IHk2h86biFxHNeRg/UfwQX3
	VQ58eW2ZJJfHTYwv7cPBcGeVd7Aufg0Ol7MI5ZbhrLXe5ZHK5liSsTeB
X-Google-Smtp-Source: AGHT+IFVYepq3n2S9z/yA3bZXGywIsGW+VrGu4X34PFTB2ZOH7zBkUvZGgUPAo/PcLR68thZfv9ZRg==
X-Received: by 2002:a05:600c:5249:b0:440:6a1a:d89f with SMTP id 5b1f17b1804b1-45b4360e8f1mr2191505e9.4.1755545529111;
        Mon, 18 Aug 2025 12:32:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcfUJtapTpDnF2IfPxbCgBvzuo7YgV5W5AYe7NVzcQCtQ==
Received: by 2002:a05:600c:528c:b0:459:d42f:7dd5 with SMTP id
 5b1f17b1804b1-45b430926c8ls993885e9.0.-pod-prod-09-eu; Mon, 18 Aug 2025
 12:32:05 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWisdLSQ/gafm8Ew57fxgs9RsxiUk4Td533Q1wBn07EANYbaIX0JiJlVKk+8tvYnxClNGtCLK2BtI0=@googlegroups.com
X-Received: by 2002:a05:600c:3510:b0:458:bdd1:b7ef with SMTP id 5b1f17b1804b1-45b436641e0mr2252245e9.19.1755545525173;
        Mon, 18 Aug 2025 12:32:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755545525; cv=none;
        d=google.com; s=arc-20240605;
        b=CXgH6QWUFpfz0fpJD8nG23JqWNofsVbnarG7LRX1o6vzbG2sm9TNlQsWkaMJl5JIrF
         G9YADkqHBHYRqufS5dREHx0y6P9wrUcXt5E7lAbt2W2Wc7+wVcG+axpYgnz6s11gehc3
         MfXbNFLk5KjK30sGo1RzYOZHxIEViAYFeBgE59aWKNuAKHOg6YChA7jV2nhSUHofrwtJ
         EeG23zhJaY32UysP63S6ipgKeawkC38Tnr5ZDMhUVtvP4hi+Au+cnvBNdrctnQ1UpNKF
         itNFF+f/kcIiZJkIdXwMEx8SG6/9eeyIgsnN65vkTlwOTc2XcHTBh93/14RirlCAZ6RV
         HC9A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=3IWli4z+BgUSiJzQPJlT48mDOgPDj86VGLzv17N+ak4=;
        fh=Q5rc+Li8QPNXc4Hz4bO6VPkGyfyW3byMD3UVaNKPLj0=;
        b=JgrkGS8i4toYLGS5ftVbC5CD/ZzFBBlpkHUzeGlxeW+zgOn6/ZR/ZyH8wpy4fySlBD
         CiAM9V/vKjw7Z0aCNW7+Hfa6nhmyxM2zit+JycBdSyrhCYdOm7GYa+fYpr+MpkeENVWT
         aMHcEfiISdjnYhRehP/iaMQz6aT4G/hUcMutUe2VHtr/7Tv1nhz58YgbEyqYk5kcq3mV
         3GsHNhE11BQ/8TS3e9UOP9s0qY9+y9l8T2MoxOwFlur8RgliSmRP9EcsC9L5LUk1EZ+w
         bDO8nzs8oU+eFuNiz0qyfTB/BR39RlJo4VH+aGzYzsiinkz70Vcx2kHPArWUUb0MSJLh
         3MVw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux.dev header.s=key1 header.b=A587SMQv;
       spf=pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::aa as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Received: from out-170.mta1.migadu.com (out-170.mta1.migadu.com. [2001:41d0:203:375::aa])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1c6cd15esi2415015e9.1.2025.08.18.12.32.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 18 Aug 2025 12:32:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::aa as permitted sender) client-ip=2001:41d0:203:375::aa;
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 16.0 \(3826.700.81\))
Subject: Re: [PATCH] kcsan: test: Replace deprecated strcpy() with strscpy()
X-Report-Abuse: Please report any abuse attempt to abuse@migadu.com and include these headers.
From: Thorsten Blum <thorsten.blum@linux.dev>
In-Reply-To: <hqvjfoaw5ooucqp3mwswrjxletq6vdzztwvlaxvxf5a6bivdzf@7fcytrsqhz4y>
Date: Mon, 18 Aug 2025 21:32:01 +0200
Cc: Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>,
 linux-hardening@vger.kernel.org,
 kasan-dev@googlegroups.com,
 linux-kernel@vger.kernel.org
Message-Id: <6BC1BD59-839C-4A3B-AE91-8CE963C891AA@linux.dev>
References: <20250815213742.321911-3-thorsten.blum@linux.dev>
 <hqvjfoaw5ooucqp3mwswrjxletq6vdzztwvlaxvxf5a6bivdzf@7fcytrsqhz4y>
To: Justin Stitt <justinstitt@google.com>
X-Migadu-Flow: FLOW_OUT
X-Original-Sender: thorsten.blum@linux.dev
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux.dev header.s=key1 header.b=A587SMQv;       spf=pass
 (google.com: domain of thorsten.blum@linux.dev designates 2001:41d0:203:375::aa
 as permitted sender) smtp.mailfrom=thorsten.blum@linux.dev;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=linux.dev
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

On 18. Aug 2025, at 20:26, Justin Stitt wrote:
> Looks good.
> 
> Here's my checklist:
> 1) strcpy() and strscpy() have differing return values, but we aren't using
> it.
> 2) strscpy() can fail with -E2BIG if source is too big, but it isn't in
> this case.
> 3) two-arg version of strscpy() is OK to use here as the source has a known
> size at compile time.
> 
> Reviewed-by: Justin Stitt <justinstitt@google.com>

Thanks for your thorough review.

Thorsten

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/6BC1BD59-839C-4A3B-AE91-8CE963C891AA%40linux.dev.
