Return-Path: <kasan-dev+bncBCLI747UVAFRBK6OQ6KQMGQETOZ5S7Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x538.google.com (mail-pg1-x538.google.com [IPv6:2607:f8b0:4864:20::538])
	by mail.lfdr.de (Postfix) with ESMTPS id 63DD8544BF0
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jun 2022 14:27:25 +0200 (CEST)
Received: by mail-pg1-x538.google.com with SMTP id 15-20020a63020f000000b003fca9ebc5cbsf11503727pgc.22
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jun 2022 05:27:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1654777643; cv=pass;
        d=google.com; s=arc-20160816;
        b=04fbVcz4h61+OByTa4uvPJb3TwniUCumlHcIzuZF0s7HHM7+zg+7J635J9WuE6bEn3
         4Lbn24HbXwEhUzU22CJyyQKF/ywLqPaX/tWGOw1XNMmy6fC25b+qZKWWmeMbD6PHdmY9
         uaAN/TBsNOJLxfVVA9gy5ryg3ryarZbG9fMeom8ugiMUf4FZYpruFzDZ7bj+JaG6+8n3
         jYFi+vJtKFEtcAbshnGvxYpDGw0x0y3Vcan6KouhJWwK4cEg8yNP+dd4PRu6ytWR42ui
         v0ibrKgG8dAsSJ6ctbJYEBEB0Ba1g5U1mRvEcBtMgzB4OBrkc2UQShwWKYdB0sdWhEeO
         qATA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=KpIIQN+k7ftCGYXE1AOAfr6TmBDSEeZFR9qWFtcqIEo=;
        b=dB9UfRHwkKiWjh3r6/tdoqr5yRtchhNvRGIcSCDoq0/qYj/4sJlgt/r8s/6SnpFmEA
         KO2cmO7jypcc5pZRDD/lP0llPiIGfymTg1FEt+0h1yApmRqkXN2YEDplv7EiKj8MX5sG
         FGoGUJlvKXhoI3CeH1r8Ocqzllyq+yZL2AlnYUGEHMZAa4iGDiQSyuj8b71X5ygxqukZ
         Lp0FqqfX66EnAEmGYaXtZ9W48y8Yn8ne4ITbdoP1GULMiTfIBGyiHN+6E54BRbfnARVW
         cCDq73zkbbKDSUjbXHdHvd+7cpvp6C68gEnel/m8Y0+xjUL20jnCVscxjdhwX0euwtNN
         y3pQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="cL/t578z";
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:date:from:to:cc:subject:message-id:references:mime-version
         :content-disposition:in-reply-to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=KpIIQN+k7ftCGYXE1AOAfr6TmBDSEeZFR9qWFtcqIEo=;
        b=ox3uLCQq7FcsOkN5ZcUj2MF2QQedrIK7LvYiX675Y+wilU7xreVPs+rGTH3Hg7HBS5
         JAIgtZG/0Ddtufr5XVbPICbnEXAkJcYljfewMBVFM086liHvh22MnSOEV9pzVFL8lAXd
         gUFPcmhX9cWN75l8Dl+XSzyy752LarVzqj3Q8vbFySSJOAYrZjaRioEeZ0K3HXzfI14F
         wIWMh0RoWAzCHZqj+07l/diyNZj1ElllAPk2opkYzhSXrNpeufIGMOtM605MN070jFbp
         v9lQb+NhG9O/R/5M1Bz1ug5gz8mU39OCQRy1WbJUlPxZHvuVEZE5kSLzO265EYxS2rko
         Vxgg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :references:mime-version:content-disposition:in-reply-to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=KpIIQN+k7ftCGYXE1AOAfr6TmBDSEeZFR9qWFtcqIEo=;
        b=iVW2SegIoBa0vq0wQVFK10MrE3/ZSAfvgrehu59EpSAurGtmPavu1yyQlFp3Rj+7Ct
         WNWWLwnw3Ngx0xuCSc+yWVn5WKSbuCyKPgVhEPkqljGa/JFy3eFyA55MvRXg/N3o6yGT
         kK5LHYQo8xawkWavPS7iGdPyyyh824f5jHuZy3OcFmQ9MjBI1/iO3nMYHKraIP/awVCB
         uYMsVShERPAhzK1PDlPX/+Gpa0PEx+cFqb0jNGxFQgnSLSYiG07Fb63STmRK73TByv/x
         AIhnGQ+JsOLOmq/g7O9bj7vmvLFXoTterX5lP52L5NAfVLHJCHyRIzVuxI4dtYYuvdPY
         xIDA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532TYg6EDho+bdAdyJT4RPgNJ+g939J5eNPH5gfpOWomnzbSe3vg
	xs1fRHGIi9wZsB6oRVI5LDg=
X-Google-Smtp-Source: ABdhPJwKfYb5FZlj8j8fJjfKdC+UQNo5V5zCHZ7TgzIzNx6Ltxsv4dtgGc6SadqYfToxsl/Bq/Jz9Q==
X-Received: by 2002:a17:90a:5b0b:b0:1e2:8e28:1a61 with SMTP id o11-20020a17090a5b0b00b001e28e281a61mr3211391pji.187.1654777643604;
        Thu, 09 Jun 2022 05:27:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a65:6051:0:b0:3fd:4bf2:e5e7 with SMTP id a17-20020a656051000000b003fd4bf2e5e7ls6231732pgp.4.gmail;
 Thu, 09 Jun 2022 05:27:23 -0700 (PDT)
X-Received: by 2002:a65:554b:0:b0:3fc:159c:823e with SMTP id t11-20020a65554b000000b003fc159c823emr34684908pgr.33.1654777642959;
        Thu, 09 Jun 2022 05:27:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1654777642; cv=none;
        d=google.com; s=arc-20160816;
        b=t+Zx4KVQuKVOB0J8x+3oY4TVvZiP9NGlARKe/OvOLWjYCZGUWNuaXdTvrwarJFdVCN
         ZMl0ii9K1DJgpDVCRamroXjyEsGpGi2kgpnD5EhiAwZgmrGvDIWxBAWEnZTJxKvhj30g
         h4G4dzDdH/1GUhFDRgZ5GYVx6Ziwr2WpsvoE5+DgkPQaC7LrgKEt85y+x6MAM29W9S+D
         qxh5JQCtuu/Xsfk3dnsWTMjfOQjO+4Z6Fe7eovQyHD2DfLxISV3CMWp39/OSc6beh2vM
         OIxxcXAS86aWgizH9EKMA8lDhvuavo+UtD8BZd9IgOVBASLx5gMKZExmkLFTYlSzjTmh
         3Fzg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=jmAyfJLi9ZPxrr5XglUuWLKXwd2sQ5F4418QWy98e5Q=;
        b=hK19jJyYGJCDVATwKK7Z0Jmk5ezUKZwElDNE+Tpu+jCpLg0vr46V/8zaQHvSsiSbi9
         EX3dcHuzjU9lIceIqlmh/uzGKALVNkkqVk5ro9bYFO/RJCsRbLFXdo2Z1p05kEDC+GmM
         mVj38F/09ERv/1S8rqiy/e955aUgaczdul7rufDrqbGVTV1MBKN2MpIg6TUQe53IGCPA
         JcCWfxGajw/Seayqpo2+/kFDK+8L/T5mxBSDOyb6VrUHlu4wOBCV0EJJeAnHsimX7oQd
         Zk7Ssp3T1aFsYVTd5yowKdDzD4kUlXQ+6D7d366WkqpFu1C3NSGHIxb8n87hTscvpzbC
         2WZQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@zx2c4.com header.s=20210105 header.b="cL/t578z";
       spf=pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id p6-20020a170903248600b00163a8206ac4si894658plw.0.2022.06.09.05.27.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 09 Jun 2022 05:27:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 6DF2560DF8;
	Thu,  9 Jun 2022 12:27:22 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 43A28C34114;
	Thu,  9 Jun 2022 12:27:20 +0000 (UTC)
Received: by mail.zx2c4.com (ZX2C4 Mail Server) with ESMTPSA id 969d3aeb (TLSv1.3:AEAD-AES256-GCM-SHA384:256:NO);
	Thu, 9 Jun 2022 12:27:18 +0000 (UTC)
Date: Thu, 9 Jun 2022 14:27:11 +0200
From: "Jason A. Donenfeld" <Jason@zx2c4.com>
To: Dmitry Vyukov <dvyukov@google.com>
Cc: John Ogness <john.ogness@linutronix.de>,
	Geert Uytterhoeven <geert@linux-m68k.org>,
	Marek Szyprowski <m.szyprowski@samsung.com>,
	Petr Mladek <pmladek@suse.com>,
	Sergey Senozhatsky <senozhatsky@chromium.org>,
	Steven Rostedt <rostedt@goodmis.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	"open list:ARM/Amlogic Meson..." <linux-amlogic@lists.infradead.org>,
	Theodore Ts'o <tytso@mit.edu>,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, kasan-dev@googlegroups.com,
	bigeasy@linutronix.de
Subject: Re: [PATCH printk v5 1/1] printk: extend console_lock for
 per-console locking
Message-ID: <YqHnH+Yc4TCOXa9X@zx2c4.com>
References: <b6c1a8ac-c691-a84d-d3a1-f99984d32f06@samsung.com>
 <87fslyv6y3.fsf@jogness.linutronix.de>
 <51dfc4a0-f6cf-092f-109f-a04eeb240655@samsung.com>
 <87k0b6blz2.fsf@jogness.linutronix.de>
 <32bba8f8-dec7-78aa-f2e5-f62928412eda@samsung.com>
 <87y1zkkrjy.fsf@jogness.linutronix.de>
 <CAMuHMdVmoj3Tqz65VmSuVL2no4+bGC=qdB8LWoB=vyASf9vS+g@mail.gmail.com>
 <87fske3wzw.fsf@jogness.linutronix.de>
 <YqHgdECTYFNJgdGc@zx2c4.com>
 <CACT4Y+ajfVUkqAjAin73ftqAz=HmLX=p=S=HRV1qe-8_y36J+A@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CACT4Y+ajfVUkqAjAin73ftqAz=HmLX=p=S=HRV1qe-8_y36J+A@mail.gmail.com>
X-Original-Sender: jason@zx2c4.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@zx2c4.com header.s=20210105 header.b="cL/t578z";       spf=pass
 (google.com: domain of srs0=tg91=wq=zx2c4.com=jason@kernel.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom="SRS0=TG91=WQ=zx2c4.com=Jason@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=zx2c4.com
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

Hi Dmitry,

On Thu, Jun 09, 2022 at 02:18:19PM +0200, Dmitry Vyukov wrote:
> > AFAIK, CONFIG_PROVE_RAW_LOCK_NESTING is useful for teasing out cases
> > where RT's raw spinlocks will nest wrong with RT's sleeping spinlocks.
> > But nobody who wants an RT kernel will be using KFENCE. So this seems
> > like a non-issue? Maybe just add a `depends on !KFENCE` to
> > PROVE_RAW_LOCK_NESTING?
> 
> Don't know if there are other good solutions (of similar simplicity).

Fortunately, I found one that solves things without needing to
compromise on anything:
https://lore.kernel.org/lkml/20220609121709.12939-1-Jason@zx2c4.com/

> Btw, should this new CONFIG_PROVE_RAW_LOCK_NESTING be generally
> enabled on testing systems? We don't have it enabled on syzbot.

Last time I spoke with RT people about this, the goal was eventually to
*always* enable it when lock proving is enabled, but there are too many
bugs and cases now to do that, so it's an opt-in. I might be
misremembering, though, so CC'ing Sebastian in case he wants to chime
in.

Jason

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/YqHnH%2BYc4TCOXa9X%40zx2c4.com.
