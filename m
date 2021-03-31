Return-Path: <kasan-dev+bncBCMIZB7QWENRBJMRSGBQMGQEM2USYHY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3e.google.com (mail-vk1-xa3e.google.com [IPv6:2607:f8b0:4864:20::a3e])
	by mail.lfdr.de (Postfix) with ESMTPS id 0781634FDB7
	for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 12:02:15 +0200 (CEST)
Received: by mail-vk1-xa3e.google.com with SMTP id k7sf528134vka.7
        for <lists+kasan-dev@lfdr.de>; Wed, 31 Mar 2021 03:02:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1617184934; cv=pass;
        d=google.com; s=arc-20160816;
        b=mTZdj9zXEyGP4Co0AwJjhAWk9WsXxVV3bniQsiGemoZ25s/dCOQkOzlTouFz44LwUV
         msfLU5c87KorOvGikv0+7GAS1nEFmSV2Y03W6nZcr6Tspy0mcqYrUEZnXTTCtNxKgmfC
         lpCMHhvO2SZZfog4xIt8oOjWZRYdeKjZYVqg2Cn7qVmdr0CC0YfUM+L46MLd+SPjc47D
         urlXZqScPjyZwnNauhuPfJSwJ8keCpsOxkm4qrJ475vfaQ9mH9WQQwbpRQfoUb3pASoX
         qrMwznaW+O3Sq/UyIh9GUZ7ONr3nCheCTCu8Qgkg0ZSxWSDNhYaRwXj3cdQP150KtVOS
         dwqw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Ow1/BEoEkzhiZKvJoK0eSnTK90m82LVd9SegZs/A3Fw=;
        b=C3rTNzhKg1+YcFkpb2LSv3KNk0JzSBFCohQ3LuTYm/W1lIDyEvjC28SmlNFDGXC9jX
         IhHa2wx1lPgKl4U2RHQKsxaEjr9NWRV2nK51tVVJEb6SB9jbXOwrZESJUKAaqXV9DJDm
         29d/+TFMX3OiunBDRZIHyaei8naLyMnyJ05xSnphUY6Uky79gkxS1ALMP9up6/1EyPqL
         I6ARrIOaHuqXSXbXA5pVSiBWIDIj6aulsHftVEa3IY9mfxdPEaGTzN4YavG078YU2Ps4
         e0eKHPEMoKGGyQEt7aOF8VGEwgDyG8MIB4lLcHjBUvj95m6rQ55IvoFLBO9Px0rBF0Te
         K5XQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVlkGVX7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ow1/BEoEkzhiZKvJoK0eSnTK90m82LVd9SegZs/A3Fw=;
        b=JhkN1ssGuAOijpcQ3Poqeq9tsqXFTlpmN0WhtwSzyPVMQw5QccFFfkUDjRBSwQbIHV
         hGjpfF66v6BjqvO94aYXt7HjgoETNLtIecXNmg4vDg/w+G8fyCHYwf/xVxPfgbW6Ty6c
         Bu6NS8Mdr2RIpjr2q7+I+k9HJqlqARgFm2LerydXD+I5TfIU8gv/S5VRkotX85HE4SPE
         iNfI/TB/2Y7TsTQnsKndP6M8QZCNVTFpgiz9tZcYrB7R4Mb/oOOwLN60J0kLoSyxHp25
         ZMVXMc6pEyfvpQH6KrUfO+kl45UJJB//LenJORawf4AGBcTiSi0ZSlh9V+7H2SRGllcO
         xJBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=Ow1/BEoEkzhiZKvJoK0eSnTK90m82LVd9SegZs/A3Fw=;
        b=uf7afsDKFJW3iuKx7bp5JxhDIhcJCu2aSLbwfXMLzHSzB+w3B4h0lUWR4OvOpJ73R2
         Y55Q5JhmDOE0Q0f3I6OkN6ru14xugM5NZ6oFIZIOpXt1raXuLjOOEs+yv+tGL7L4hih7
         /YE+ozhl8MDLF8Bn6M/YFdmEbDRZN5MYN/tVD1RSAtYjeegyvo0sinFtXgYF9Azj88bF
         kc3wJA4Nkq87e16OvKrpDRcSnK6GOhM740Fy4oTkhj7Odu4EWSjnUQXAswqr4Gr9+E3u
         hLM8V/YHblCs3pMe7NNfGs4WSH4DegCejkCdAy3XGr7hETwvGj4i4pXH/8YqrDBmckO7
         P2+A==
X-Gm-Message-State: AOAM5332Rits6DBNf5b+c68eoMslZm45bsgPd0C9dR4GUhNJcs2VRX4y
	JSGWr/LMP5NUUYL14Kx8SJI=
X-Google-Smtp-Source: ABdhPJyc96nnN4FgKWO/ni3oIlhfg2jhPrGJsM9bgWeQ3hY9JQJI7h4Hoy2TmCNwqGdOcPVxpfF9Cw==
X-Received: by 2002:a1f:7889:: with SMTP id t131mr1140116vkc.2.1617184934017;
        Wed, 31 Mar 2021 03:02:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:3b93:: with SMTP id p19ls108912uaw.8.gmail; Wed, 31 Mar
 2021 03:02:13 -0700 (PDT)
X-Received: by 2002:ab0:390d:: with SMTP id b13mr800189uaw.53.1617184933546;
        Wed, 31 Mar 2021 03:02:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1617184933; cv=none;
        d=google.com; s=arc-20160816;
        b=rZ3Q2ms1pJ3nuMIClZAKoG3DVXg2utfdHHcdJy97LHtQhtY9gFQCoEqiBKEY+rHbQ7
         zm/m3NTwAEo8SCbh/DIK2+qFdcntSlQ/U77gI4Kajap61xnHywnaVg9wGw6vfcA7s3vX
         lLvx0FuEY70Uz6y2zb6zBM1F/AeMmb0NBaLtVKmdKDypk2VSB8lHPaw2eta5qqlURpFb
         HRxl3jBMJL+xWFaOIACznRndYaixTUDrND7U4vwK/EIjWdBLKU1HXSFK/6amn62jLKvf
         xnDufIqwBsWPRds+XPJBWfYAqFJX8fSETbizcoT5rydEGJrKmGa22y4avwexF6pukEvl
         BaBg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=JWD91za5LG36WAQIn/p+7RREk6zwz1h7XL1Oim6J9qY=;
        b=fWI5jT+TlqQnlH0O0oFgjuXderWUrDRWxdJki+SB0l0H1Ums9mzUrYHXDDTuB78iP5
         3gGszuDKMRYWd3tWucGYNepfUI6xCQPCNZSUeTu1Niy6nnTuPwrAiDOOHFMgpT9oHP3+
         Z6qfebeJZCXnXL/q+dR9kTfAzUmkPsCsmlHZkHvK9OPg+eQyTNszlUQduOc7zI2r8cto
         qoHZaGLgm4+fv/w19fFIiie335LofEY26eqi5neTJfkED1WhkB/r7hUAWOlQduyvxeCP
         AgbnzBcPtmNEl8+ExyUHmhqOTBPySD61TFpY4/4tnJMUqjb4UN8BJNB03UUHqsEfYCMG
         mCdQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=LVlkGVX7;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id r17si100217vsf.2.2021.03.31.03.02.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 31 Mar 2021 03:02:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id t16so9577843qvr.12
        for <kasan-dev@googlegroups.com>; Wed, 31 Mar 2021 03:02:13 -0700 (PDT)
X-Received: by 2002:a05:6214:2607:: with SMTP id gu7mr2176202qvb.18.1617184932943;
 Wed, 31 Mar 2021 03:02:12 -0700 (PDT)
MIME-Version: 1.0
References: <20210331063202.28770-1-qiang.zhang@windriver.com>
In-Reply-To: <20210331063202.28770-1-qiang.zhang@windriver.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 31 Mar 2021 12:02:01 +0200
Message-ID: <CACT4Y+b91FHrbgqSzhmZ6j_u9v2B4YrWU9GMomQp9rS-sGM5SQ@mail.gmail.com>
Subject: Re: [PATCH] irq_work: record irq_work_queue() call stack
To: "Zhang, Qiang" <qiang.zhang@windriver.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Matthias Brugger <matthias.bgg@gmail.com>, Andrey Konovalov <andreyknvl@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Oleg Nesterov <oleg@redhat.com>, 
	Walter Wu <walter-zh.wu@mediatek.com>, Frederic Weisbecker <frederic@kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=LVlkGVX7;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f2c
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Wed, Mar 31, 2021 at 8:32 AM <qiang.zhang@windriver.com> wrote:
>
> From: Zqiang <qiang.zhang@windriver.com>
>
> Add the irq_work_queue() call stack into the KASAN auxiliary
> stack in order to improve KASAN reports. this will let us know
> where the irq work be queued.
>
> Signed-off-by: Zqiang <qiang.zhang@windriver.com>

Reviewed-by: Dmitry Vyukov <dvyukov@google.com>

> ---
>  kernel/irq_work.c | 7 ++++++-
>  1 file changed, 6 insertions(+), 1 deletion(-)
>
> diff --git a/kernel/irq_work.c b/kernel/irq_work.c
> index e8da1e71583a..23a7a0ba1388 100644
> --- a/kernel/irq_work.c
> +++ b/kernel/irq_work.c
> @@ -19,7 +19,7 @@
>  #include <linux/notifier.h>
>  #include <linux/smp.h>
>  #include <asm/processor.h>
> -
> +#include <linux/kasan.h>
>
>  static DEFINE_PER_CPU(struct llist_head, raised_list);
>  static DEFINE_PER_CPU(struct llist_head, lazy_list);
> @@ -70,6 +70,9 @@ bool irq_work_queue(struct irq_work *work)
>         if (!irq_work_claim(work))
>                 return false;
>
> +       /*record irq_work call stack in order to print it in KASAN reports*/
> +       kasan_record_aux_stack(work);
> +
>         /* Queue the entry and raise the IPI if needed. */
>         preempt_disable();
>         __irq_work_queue_local(work);
> @@ -98,6 +101,8 @@ bool irq_work_queue_on(struct irq_work *work, int cpu)
>         if (!irq_work_claim(work))
>                 return false;
>
> +       kasan_record_aux_stack(work);
> +
>         preempt_disable();
>         if (cpu != smp_processor_id()) {
>                 /* Arch remote IPI send/receive backend aren't NMI safe */
> --
> 2.17.1
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2Bb91FHrbgqSzhmZ6j_u9v2B4YrWU9GMomQp9rS-sGM5SQ%40mail.gmail.com.
