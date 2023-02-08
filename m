Return-Path: <kasan-dev+bncBC7OBJGL2MHBB75JR6PQMGQEEAYX5TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113b.google.com (mail-yw1-x113b.google.com [IPv6:2607:f8b0:4864:20::113b])
	by mail.lfdr.de (Postfix) with ESMTPS id 56E7E68F3E2
	for <lists+kasan-dev@lfdr.de>; Wed,  8 Feb 2023 17:59:45 +0100 (CET)
Received: by mail-yw1-x113b.google.com with SMTP id 00721157ae682-4bdeb1bbeafsf179518277b3.4
        for <lists+kasan-dev@lfdr.de>; Wed, 08 Feb 2023 08:59:45 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675875584; cv=pass;
        d=google.com; s=arc-20160816;
        b=dnIwNnR0beZPnYRSVzgYs62Ea+FLBaeYHLqEVvn7dW+On9XMD5eKxWq44GlU6eCziQ
         fV1peAAJkR41FO8aXfYx7qTNwKvrddxCTMZzmMqv6Er7tnUOEvN6ijocD9vCDt1yUwz+
         ZiMW4GmahDNRJuWatwMyOp2XcQ1YitUg5aa+J+FjIZJY+HdL6Rz1sUmkNOIn17ghWemX
         K0hT6QHg5fpH6l3lM2KL9Gt+c13IeQ3GBB2OLP2LfQMbrfKJ0P4m8SuDIYs0H1r+E6wa
         58ZkrHKPcYID6xI9XF2pay72TQbWU8rtHRh+WscssNHFxqV+vK8Gw0+fdhrQF5SsVmhH
         wkew==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=KPenMFdtFiUUBK4pB5LZnFGgw9mG7becXiRA8LR/59M=;
        b=NHsjmH321nKjyQT0JjAc+zR13Hcgk6w6qgCeMyx/lC3CYu4ZOPFLJlzZtFPUqpKnZv
         xqXH6ipIrg4iJSpOZj8v7M/rROL7uT3WW2wWiOupypsoJzFrfmkj7xD5IoL5gOQEy9rV
         dGDuMz2lh3s/oX1QCpvxMQv4MZTseoVGdUdQ9QRyGObQ+48OW0KKrw4M3uFFX1GRf/wR
         N9aT3WRcEyNpevzpmIZdfQBzimwBe84JSmNEhsvU1/oKinmhoQ7HFqtow0FXiY8v0sj7
         MZvueFOPFA34wDT6obDk7gOacHNNkwqbUGJ5hOXxbl90hZC9OfvemkIAz/xzdAaRu8r9
         Q5eQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hdxm4WQn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=KPenMFdtFiUUBK4pB5LZnFGgw9mG7becXiRA8LR/59M=;
        b=mPagi6l9pITz7MQIkdMt/GTXlqqV0gBU7/UJftROhGpRSmGMChYcCwKQaPcU1MBG2d
         /ygaK3UEcp1v9XfPn+CeidPttYMUeZa19oGe6/Odra1iAVwZCWTw1DKMbCyV84QXhAOX
         bGrspyf8spr+Bd5BlqNE7REgFfrAvyTIUp0GjXBDbfKmjn4L77Pu/iLx21TFwag/0vHm
         S+y3W2FcEqHzMaQeXz+hyu1WxO70mzwBYBudyunK4iOhUoZEx5zWZjNZlps3IOdswJv5
         LzVpX7UyUGzWTTzSJ6cANiSQa/dgRLctILs556kSgoS382/5GNRM3+mzrKx+jwKZNXV9
         O1wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=KPenMFdtFiUUBK4pB5LZnFGgw9mG7becXiRA8LR/59M=;
        b=hybY23YXWrwE+b5nAgBDdVK9h2jHXLIw8jxWOl/lwxht+Tu6+iR9YmidMG16iQewK8
         bRUqNy0JDf55pvFUhAlqzlepbud2rI06t7+aAh4nbgP1AOuOMzawX+CkZ0L98xv2hV9n
         g5rtfQrE8vGS+MB9BXmwppq/9mIOsBtVybf22nz28SKxt/708Lr4a3PnC0lRrka1ntjg
         x4ShbEfGtuO5YW+Nz8WbX47EHpcmUnFE2mQVKGtAnTMRYMabic2qLTcXezlhMyE/n3yQ
         sB68yPRgobjpi5DU1InZy9o0veMh+syptlbwyxkOWnKAkBcXaVrnVZ7khvtIl99tUHIj
         rxrw==
X-Gm-Message-State: AO0yUKXPC7v4z+ivEq7cMpOUALD6R8p4tCgB3szzch8Z5yJ7gEA61okR
	HVH1D6S+w+4VJ+XMONwoSZE=
X-Google-Smtp-Source: AK7set+CAvMQD3bwBMp8eDo7y7V1JF37iBWrtQrmqel2lePLiw6MIvgPt0Sptbd3wGs3q3K9rgF1BQ==
X-Received: by 2002:a81:8004:0:b0:4b0:84a1:3a9d with SMTP id q4-20020a818004000000b004b084a13a9dmr1089959ywf.66.1675875584079;
        Wed, 08 Feb 2023 08:59:44 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:8944:0:b0:51c:41db:8e2d with SMTP id z65-20020a818944000000b0051c41db8e2dls9549040ywf.1.-pod-prod-gmail;
 Wed, 08 Feb 2023 08:59:43 -0800 (PST)
X-Received: by 2002:a81:b54d:0:b0:527:2c00:e4e3 with SMTP id c13-20020a81b54d000000b005272c00e4e3mr4246717ywk.5.1675875583317;
        Wed, 08 Feb 2023 08:59:43 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675875583; cv=none;
        d=google.com; s=arc-20160816;
        b=NoHVXs5JkbP1k/Qqwq3NIk96pHGO0zQ7VjXUOTpCQCkTzbGJlBfILat/Bu5uRlVdKH
         xAv8gEsh1cgs2COmCMEMevXmbM5rBDCrXA1p9kSNCoHt3xB89CiwAGiu3bZ1oTQVPpXv
         gGikmi0X3I2lE6XVPozYcf3Hj0DGGn768H+iWwmiWZDYFJENgbrT71M6k+iaGurETHvX
         zzaLQqbsZNG+3ykqX9Uh7U4naVdYElkVPRWpLVrPTp3l4Yl3qE9lfUhGpK6/wwi3qXfA
         AwbhHi52V1DydTFz//B1vG/ft+1YBvUxn2kMTCIfXMBp4VfQcuFDJxuYvESbAh0Qm3Qv
         F5Ig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=mdP6aBj8Z0tyjtWe/gNi4Xtx2Z1yUcQKnx0+gFKe2qI=;
        b=l3rTgV3UtjJrFOJGpOkwfXS56nYnIgQ+/+d/ngbmDVVvW2NHwwrcPKJhSkftIGJg2u
         /qhHNKpmxBIIWKyaR6TE3+p3vg8umTQIL5KRtZr9NG7fBypBdoXhkQzSrplF50NE6tAr
         B2IXWBThI/6/qdZjut+IxiizieXqxa5tq9bld2G6BwryJHq1wtUPGxvu7yuBUFMvLlB2
         n7uSy7uKpcBbWwQ2Xay3FLtKmEFBr4C7o/XAkfbJhM0fjZE4Yr50T1qvv+TY0vCTNd/Z
         Os/zLCWh8JK5gLPZwwXnx1+gbAl8cXk6PPOxr47V3P/Ia9zHdpXANlcgf/kwZ9gL21Fk
         5uUA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=hdxm4WQn;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-yb1-xb2f.google.com (mail-yb1-xb2f.google.com. [2607:f8b0:4864:20::b2f])
        by gmr-mx.google.com with ESMTPS id bj6-20020a05690c044600b0052bcc1e1c79si283436ywb.2.2023.02.08.08.59.43
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 08 Feb 2023 08:59:43 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as permitted sender) client-ip=2607:f8b0:4864:20::b2f;
Received: by mail-yb1-xb2f.google.com with SMTP id n139so5564968ybf.11
        for <kasan-dev@googlegroups.com>; Wed, 08 Feb 2023 08:59:43 -0800 (PST)
X-Received: by 2002:a5b:4cf:0:b0:87d:c01e:2205 with SMTP id
 u15-20020a5b04cf000000b0087dc01e2205mr1295357ybp.179.1675875582673; Wed, 08
 Feb 2023 08:59:42 -0800 (PST)
MIME-Version: 1.0
References: <20230208164011.2287122-1-arnd@kernel.org> <20230208164011.2287122-4-arnd@kernel.org>
In-Reply-To: <20230208164011.2287122-4-arnd@kernel.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 8 Feb 2023 17:59:05 +0100
Message-ID: <CANpmjNN1nmjavBhj=xMMqAD1VScPySkdZbm2sTpWnKN1ZvmJcQ@mail.gmail.com>
Subject: Re: [PATCH 4/4] objtool: add UACCESS exceptions for __tsan_volatile_read/write
To: Arnd Bergmann <arnd@kernel.org>
Cc: Josh Poimboeuf <jpoimboe@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	Borislav Petkov <bp@suse.de>, Will Deacon <will@kernel.org>, Thomas Gleixner <tglx@linutronix.de>, 
	kasan-dev@googlegroups.com, Dmitry Vyukov <dvyukov@google.com>, 
	Alexander Potapenko <glider@google.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Arnd Bergmann <arnd@arndb.de>, Miroslav Benes <mbenes@suse.cz>, 
	"Naveen N. Rao" <naveen.n.rao@linux.vnet.ibm.com>, Sathvika Vasireddy <sv@linux.ibm.com>, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=hdxm4WQn;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::b2f as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 8 Feb 2023 at 17:40, Arnd Bergmann <arnd@kernel.org> wrote:
>
> From: Arnd Bergmann <arnd@arndb.de>
>
> A lot of the tsan helpers are already excempt from the UACCESS warnings,
> but some more functions were added that need the same thing:
>
> kernel/kcsan/core.o: warning: objtool: __tsan_volatile_read16+0x0: call to __tsan_unaligned_read16() with UACCESS enabled
> kernel/kcsan/core.o: warning: objtool: __tsan_volatile_write16+0x0: call to __tsan_unaligned_write16() with UACCESS enabled
> vmlinux.o: warning: objtool: __tsan_unaligned_volatile_read16+0x4: call to __tsan_unaligned_read16() with UACCESS enabled
> vmlinux.o: warning: objtool: __tsan_unaligned_volatile_write16+0x4: call to __tsan_unaligned_write16() with UACCESS enabled

That's odd - this has never been needed, because all __tsan_unaligned
are aliases for the non-unaligned functions. And all those are in the
uaccess_safe_builtin list already.

So if suddenly the alias name becomes the symbol that objtool sees, we
might need to add all the other functions as well.

Is this a special build with a new compiler?

> Fixes: 75d75b7a4d54 ("kcsan: Support distinguishing volatile accesses")
> Signed-off-by: Arnd Bergmann <arnd@arndb.de>
> ---
>  tools/objtool/check.c | 2 ++
>  1 file changed, 2 insertions(+)
>
> diff --git a/tools/objtool/check.c b/tools/objtool/check.c
> index e8fb3bf7a2e3..d89ef6957021 100644
> --- a/tools/objtool/check.c
> +++ b/tools/objtool/check.c
> @@ -1200,6 +1200,8 @@ static const char *uaccess_safe_builtin[] = {
>         "__tsan_atomic64_compare_exchange_val",
>         "__tsan_atomic_thread_fence",
>         "__tsan_atomic_signal_fence",
> +       "__tsan_unaligned_read16",
> +       "__tsan_unaligned_write16",
>         /* KCOV */
>         "write_comp_data",
>         "check_kcov_mode",
> --
> 2.39.1
>
> --
> You received this message because you are subscribed to the Google Groups "kasan-dev" group.
> To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
> To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230208164011.2287122-4-arnd%40kernel.org.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNN1nmjavBhj%3DxMMqAD1VScPySkdZbm2sTpWnKN1ZvmJcQ%40mail.gmail.com.
