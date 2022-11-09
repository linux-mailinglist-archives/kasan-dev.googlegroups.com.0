Return-Path: <kasan-dev+bncBCB33Y62S4NBB55RWCNQMGQEBQD6ACY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-f183.google.com (mail-il1-f183.google.com [209.85.166.183])
	by mail.lfdr.de (Postfix) with ESMTPS id D479562359F
	for <lists+kasan-dev@lfdr.de>; Wed,  9 Nov 2022 22:17:44 +0100 (CET)
Received: by mail-il1-f183.google.com with SMTP id z19-20020a056e02089300b002fffe186ac4sf140274ils.8
        for <lists+kasan-dev@lfdr.de>; Wed, 09 Nov 2022 13:17:44 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1668028663; cv=pass;
        d=google.com; s=arc-20160816;
        b=Z6v+u0yjavH+hLJpNSeErRBJlJs/k4Pl3NJNs/Q/YvbeTZFk4v05cXeNxIKdXP4QIJ
         A5Qi2HdZaFgmgfu0N8v9la3A2DB8vnD3nyax5iXBd7VB2Ly9e3lQ0tiUkcN7T9Qhf10i
         0UJiaDnLWYVhcAsO+A+8WNjS/+d5LcFycGnHTC5AgQn4NaipDlDuJdASyG4MOghsONg/
         1PRVfrxw0lZVddg9O1cLrBqA23loO9fPbK91s0nl0LwMwgwcUvXvoMK4xrNRWJRm8F4h
         5DxUpSuKEOQcsENbJVx42XcSoI4assXdXhlOSVgyGf64m22tto+D3+aK80PRdKDPhAU1
         vzGw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date;
        bh=wZIUwpqJdIfSbcT4VStYL1dSHfeJGBC+aatigJKgEpc=;
        b=MC0SflJH7W0TAKJ4OqqoEItX2UDi3hJ5iFIoBg76m/Od1IDcW3nsDkmZXVaJDVQ65r
         6a0n1YR0Cq/5v/c/mZhkLgT5XogiP1NfDoXFtBMzzs+4BN6wKYVkNegmSYt100Cj/fyw
         ImhFDFCzWcCuqP4ocveFVrU5k93cVNaW2JcQpTQ0ovXrTl9AOstKLSm7e/5t6XFEOXoZ
         Rs4BuSy9Yq4sXptfvXk1T5/+Q9s+0GkC2tzSw9JV3gnS/o7Pzab2xvOuOxSxGQDvtvX6
         qw/M32GT1w4yesirmqRMA/3qJ6s90nMUKs1nq0rVA99x+8yHDjg1cGjnL41veYekl9OV
         tVHg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=yTyMtQVI;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:sender
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=wZIUwpqJdIfSbcT4VStYL1dSHfeJGBC+aatigJKgEpc=;
        b=Ofpoi90KNWgrBwshH/ViwdEcfLKmALG1owFiXNfQvGQa3TY/DuGJdem9qicDh8TL//
         njF3MkImOXtYvO4zw4bZMyNbGZVdxdr0IFjdumlrwSKrjBQVx6gNDbvVrja4aYnNHy9O
         Kv0i4N5JyUSrJfNwyGKo/S0RCKoSIh/JmQxGEX2NwQmwI5YkvT0HSEd+GlfcKqTn7+0B
         +ak7lZL9rlLmfmQ7JsiQQDbt0Alouj9iMlH8oQ2Gl5QU+U5jabJhu0qDSwMsFBeCXa++
         lGlkrJ0XUqOGBN8teOKjS3semvZqq8mYsXFcHkJNS96+U0BDKqiA/nDiGFIZJi/+Zoh4
         rdkw==
X-Gm-Message-State: ACrzQf2XKZ6Bh/7etQIp9xGKsyGi52XrOTTh+RvRDKZeP1DxYGrnD3qN
	LwaPHdTS1k9/yKLKkUrwVHg=
X-Google-Smtp-Source: AMsMyM7daxyBd+nyQEgG+JBRLCqnJ4y/iB4hNEcGrlhncWUsow4imH848JRl3bq+PmBn1AJHS0UCSQ==
X-Received: by 2002:a92:cd82:0:b0:300:1983:fd78 with SMTP id r2-20020a92cd82000000b003001983fd78mr34172086ilb.248.1668028663702;
        Wed, 09 Nov 2022 13:17:43 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a02:620a:0:b0:358:3055:3faa with SMTP id d10-20020a02620a000000b0035830553faals34643jac.6.-pod-prod-gmail;
 Wed, 09 Nov 2022 13:17:43 -0800 (PST)
X-Received: by 2002:a05:6638:1515:b0:363:b7d1:c3b7 with SMTP id b21-20020a056638151500b00363b7d1c3b7mr34668118jat.46.1668028663243;
        Wed, 09 Nov 2022 13:17:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1668028663; cv=none;
        d=google.com; s=arc-20160816;
        b=MvxrzLudS4/E2kxTf+wtiNpCSzI2L+WK9dHCWOUkuUEH40iT7fXKZSd+JOFTJ/VZlz
         O9z2X+Te4OduCwUOrArXNiGE8YXNntYx77KMih6mgVvEoyRU2psjYfoj3vMQLkO5OjFc
         Q648VhDVNZR4Fr43Ik3mGDPJz3DXTNFf89xwGg5+UqBtKT1dTbc0ZejTOk0eEl1X1LX4
         LTXC5ZaNxHhr50gsQz34glL4xciIYouZIfDt487Jc4VMzNs3y0yWI4lq9S4D5WaNXtVR
         KhL3bcHkDgtUgGGwVbB2nuR8VoOe0/PmzRqRSjB6iokEJr1wIoO427pnrcwFwm1+KonE
         kfow==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=sender:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=c2Wy125HjX2W7gqEInmUWaHL+2Vak7X60gZ/uKVxsSs=;
        b=MF9N6wvuY2PwtY2ZZiRNXKysrc9RG/fQsSFKg6qTS2Ju6enMbl9AnV3VZC7QyQI/Oc
         ZHDJZSw/TEIrjH3SoJge3eOQqlw1+Lx7ifFbxWwNDpkqGnMSwn252OpO2cC11OHOcC/m
         0gOElr/r1YEwVjggM8BMQwrB66q6CKIvyZCEpQh3bVpe3QvUHJCS1jNQs8Js0kX3/1Xt
         9PPmj5LOjyegw7xdNFSqod6SwrpubrqeNUFgd1PlMvlux4l1yJzh80edhKnb7Wh+d8oh
         awpt1lo5Mk30QdzI5aOVHdJpJ03c6vPFdidYHZZMHC0roj8XA9u+KOkvqzgfXRYzW85Y
         T/GA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@infradead.org header.s=bombadil.20210309 header.b=yTyMtQVI;
       spf=none (google.com: infradead.org does not designate permitted sender hosts) smtp.mailfrom=mcgrof@infradead.org;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from bombadil.infradead.org (bombadil.infradead.org. [2607:7c80:54:3::133])
        by gmr-mx.google.com with ESMTPS id t7-20020a92ca87000000b00300c4b978d7si714667ilo.2.2022.11.09.13.17.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 09 Nov 2022 13:17:43 -0800 (PST)
Received-SPF: none (google.com: infradead.org does not designate permitted sender hosts) client-ip=2607:7c80:54:3::133;
Received: from mcgrof by bombadil.infradead.org with local (Exim 4.94.2 #2 (Red Hat Linux))
	id 1ossRG-00HMpa-89; Wed, 09 Nov 2022 21:16:50 +0000
Date: Wed, 9 Nov 2022 13:16:50 -0800
From: Luis Chamberlain <mcgrof@kernel.org>
To: Kees Cook <keescook@chromium.org>
Cc: Jann Horn <jannh@google.com>, Greg KH <gregkh@linuxfoundation.org>,
	Linus Torvalds <torvalds@linuxfoundation.org>,
	Seth Jenkins <sethjenkins@google.com>,
	Andy Lutomirski <luto@kernel.org>, Petr Mladek <pmladek@suse.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	tangmeng <tangmeng@uniontech.com>,
	"Guilherme G. Piccoli" <gpiccoli@igalia.com>,
	Tiezhu Yang <yangtiezhu@loongson.cn>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	"Eric W. Biederman" <ebiederm@xmission.com>,
	Arnd Bergmann <arnd@arndb.de>, Marco Elver <elver@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Peter Zijlstra <peterz@infradead.org>,
	Juri Lelli <juri.lelli@redhat.com>,
	Vincent Guittot <vincent.guittot@linaro.org>,
	Dietmar Eggemann <dietmar.eggemann@arm.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Ben Segall <bsegall@google.com>, Mel Gorman <mgorman@suse.de>,
	Daniel Bristot de Oliveira <bristot@redhat.com>,
	Valentin Schneider <vschneid@redhat.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	David Gow <davidgow@google.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Jonathan Corbet <corbet@lwn.net>,
	Baolin Wang <baolin.wang@linux.alibaba.com>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Eric Biggers <ebiggers@google.com>,
	Huang Ying <ying.huang@intel.com>,
	Anton Vorontsov <anton@enomsg.org>,
	Mauro Carvalho Chehab <mchehab+huawei@kernel.org>,
	Laurent Dufour <ldufour@linux.ibm.com>,
	Rob Herring <robh@kernel.org>, linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-doc@vger.kernel.org, linux-hardening@vger.kernel.org
Subject: Re: [PATCH next v2 0/6] exit: Put an upper limit on how often we can
 oops
Message-ID: <Y2wYwsolgpRGPuMK@bombadil.infradead.org>
References: <20221109194404.gonna.558-kees@kernel.org>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20221109194404.gonna.558-kees@kernel.org>
Sender: Luis Chamberlain <mcgrof@infradead.org>
X-Original-Sender: mcgrof@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@infradead.org header.s=bombadil.20210309 header.b=yTyMtQVI;
       spf=none (google.com: infradead.org does not designate permitted sender
 hosts) smtp.mailfrom=mcgrof@infradead.org;       dmarc=fail (p=NONE sp=NONE
 dis=NONE) header.from=kernel.org
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

On Wed, Nov 09, 2022 at 12:00:43PM -0800, Kees Cook wrote:
> Hi,
> 
> This builds on Jann's v1 patch[1]. Changes in v2:
> - move sysctl into kernel/exit.c (where it belongs)
> - expand Documentation slightly
> 
> New stuff in v2:
> - expose oops_count to sysfs
> - consolidate panic_on_warn usage
> - introduce warn_limit
> - expose warn_count to sysfs
> 
> [1] https://lore.kernel.org/lkml/20221107201317.324457-1-jannh@google.com
> 
> Jann Horn (1):
>   exit: Put an upper limit on how often we can oops
> 
> Kees Cook (5):
>   panic: Separate sysctl logic from CONFIG_SMP
>   exit: Expose "oops_count" to sysfs
>   panic: Consolidate open-coded panic_on_warn checks
>   panic: Introduce warn_limit
>   panic: Expose "warn_count" to sysfs

For all:

Reviewed-by: Luis Chamberlain <mcgrof@kernel.org>

  Luis

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/Y2wYwsolgpRGPuMK%40bombadil.infradead.org.
