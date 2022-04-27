Return-Path: <kasan-dev+bncBDAMN6NI5EERB6MJUWJQMGQE2G6G56I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43f.google.com (mail-wr1-x43f.google.com [IPv6:2a00:1450:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id C8C2F51184F
	for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 15:28:25 +0200 (CEST)
Received: by mail-wr1-x43f.google.com with SMTP id v29-20020adfa1dd000000b0020ad932b7c0sf770966wrv.0
        for <lists+kasan-dev@lfdr.de>; Wed, 27 Apr 2022 06:28:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1651066105; cv=pass;
        d=google.com; s=arc-20160816;
        b=fuxOJU0HaRiDTtfFZMzd/GYjwqN2uP42nukYbItxvEa7O0WMw83QLWE6TefhxlzvR4
         Zgp0mZFOljvU6qVrTNTLfFp38wsfQTtp4BWCJeWS7G386ft0srH9ItztnUkynNi5VV4G
         lxIEOPlIG86IcTJjhtmIHMd94KojHf8fiHLUPylS7Drknt6qku1wUjCTvtYfQ4G+tWMm
         2CA8HHDntYEZDSEtjc7i+QpcKpPK4mBkKybmDAOMajnXSvxe39eWC43h0Xj3AxdTqh2T
         Zpfb7RnTIVheRtbWkpcrOLLjDqJZSaUeQ/er5AxeDpum3whcVNTiJJo3Qp2y3ickpV5N
         81Yw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:cc:to:from:sender:dkim-signature;
        bh=GIso/YtOHyL4ZiCpXjFCboUWwoYwcz+Lq0FFPkruO7g=;
        b=09NAokCzL/M6ed/FTFQP/ConBAL8WgA97P6d5EtKP9PWHWNL81ffNv14erQ88nuZfW
         cXDIgdskRa3woP0MCTg1i+pn4zegvlklW73NILJ0pg9KEXAbUlp0V5i/GW+JcEA4QaD+
         rwtkWWXHPAPX+dxMbANc4aBWtBBOyNgHvfHwH1LtoDCF4v7S7U6klwMzkZnqoUI/fbEi
         gB+WXTF92NnKFtfJkb+hhD5BO2UhaqPynOj1t64YarSXeM/EwwcIEspb8snDNKT2P5ZN
         Jtr9gHM4fhr1djvFTGptCiqyumnMIgqrBTp9EvvGk4qTqv1y4bhmiDV6ygXO5DMA/LNL
         sU8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=CnD8+0uD;
       dkim=neutral (no key) header.i=@linutronix.de header.b=mqNvTWF9;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GIso/YtOHyL4ZiCpXjFCboUWwoYwcz+Lq0FFPkruO7g=;
        b=ZdqW7s77yDNvtNHK7Yd7vrqTEREeDXWu4qmYv+Yb3TBntlrDfSeWuc93jS5gTYc7+m
         bpV65j/kjxrehbZCRLDhthQGqiUManuz0xhNhSRd0Shb3PMRyiFYKk0/EjtTkUgIPQyT
         Ob3XUqhuhaT4iZipop8DRAWSI9c4o2Htf9ZCC8g+fCwCPO914G+mKQu/j0IGDZ8rShjm
         qrcNgSilGDDVqPxTFcojFqIeYnwfMRWoPMH+7662Bn9IwbaorshJ7JlbXR6a9KVzJUwf
         b209gxOhptvL1GCskT/zRifa9NxksyAEP75qDUKWYzshhwSplyjn0tEQ6VNmOnplnCvl
         VN9g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=GIso/YtOHyL4ZiCpXjFCboUWwoYwcz+Lq0FFPkruO7g=;
        b=sxq3JZ5wZ/hyQg/Asr/ngu+9oBtd7JM6U1aWxDwcwg9G5m8l6EUP3o2bi7tW2l94VG
         sUpgWJE890P6Czk6k4bSKzr00lUDT2hAjO/SKcFTLs4uA9s/tYrNVeMnhkyx6MQ873U/
         dwwkfG+fR5ROrBcc2NuUmwgOhogcxy5BMmOii5f4DQGrEjXRnqbbebPIRyeFdSv0j0Yu
         GGP+BKh3PumGNc3DeFiHYx4If2Zs9lob0gfX6fm6sLNjDDtVzLbyAo5eJvrhq4RRcgBA
         /xhm/iq83UzJQOxtHP6rH+Tvcelf/nVgSRSyy5pfHftVCsha33iMysHpJAw3eYBVj2fr
         A9jg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531UVyWKHVF5AXx60PudgHB1+Q4e0PLDDPVSktBXjjm18tumxeAg
	7bz5tfiBurMHiEH/8M2k9tM=
X-Google-Smtp-Source: ABdhPJzhqyqfY3B+aEyBiNgnpaU1xa1kDI6R8VeBkJovfPq4hGhXUSDY686K2Tc8J2+WKt7TVDJgWA==
X-Received: by 2002:a05:600c:4f4d:b0:392:9169:35c8 with SMTP id m13-20020a05600c4f4d00b00392916935c8mr35569053wmq.36.1651066105394;
        Wed, 27 Apr 2022 06:28:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:6d84:0:b0:20a:eafa:40fb with SMTP id l4-20020a5d6d84000000b0020aeafa40fbls3443804wrs.3.gmail;
 Wed, 27 Apr 2022 06:28:24 -0700 (PDT)
X-Received: by 2002:a05:6000:15ce:b0:20a:85e7:f8b9 with SMTP id y14-20020a05600015ce00b0020a85e7f8b9mr23158823wry.68.1651066104452;
        Wed, 27 Apr 2022 06:28:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1651066104; cv=none;
        d=google.com; s=arc-20160816;
        b=zSneOcEqcaufsKfCJ3Dy9RVw/Hqph+FZRTZMWTb1nz0++/o9sEZ6sVM+qUmzzMY3vd
         C+F7goW/yzxlIXkzG/J+iU2/FVhIpM5SlvxwipivmPNVVxLS/Gd3w/vtrUOxyT4EcxNf
         CHTp8aM8prVnjL7KDu40AHB9pxjeLP527v1foJGQLhqYfAYkrS3FOWfzuvSVYWOOJ/vX
         NcJREVKjLn5ToSmr/7KoZziXM7xGTLdGTG/RR9mceVP05NtqT1OgqQ1vtID4tvlOEaxr
         D8FzPcvr/Hr+3ut+Wxa416ixbqD6u1vMiylpxuJ8RKUtoKqJFMm2RbMTg/PHWhPXU7/2
         WqJw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :dkim-signature:dkim-signature:from;
        bh=XeLkj9226T84S9BXMt19LKkxjN+pWXBCLzkSQX80Wy0=;
        b=CN0MqwGGYuB7+Kvynb5zMifFQEb6YsAJKHjBzeyNWk0Z2sFiPm1rCsulX1vsVQ3lsh
         MY6PC+BtBsGehYTJKrcnM0GNnrjm2uPUE+02aYgQZg/GqqNMH9xRWA7GxnhKVsdFWp3N
         PDUi64d+OQnp478TlEMwOHCcmkijjuGVg3bxK14qRgTISWDO1EWW/ryDfPLlrE8wKkZH
         /eq2Dk0jAeaLoi7G97IpKWllQR6yCpgBfV0hR3O3siruyR2h93lF2CaRji5Qd5OFkk5h
         eNXZNZHRc5rXvD6zLj6njT2+JLkR9mRl2AfvBpWMCEUgo8e96Yvuo/B+DFINCrL16p0l
         FtTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linutronix.de header.s=2020 header.b=CnD8+0uD;
       dkim=neutral (no key) header.i=@linutronix.de header.b=mqNvTWF9;
       spf=pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) smtp.mailfrom=tglx@linutronix.de;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=linutronix.de
Received: from galois.linutronix.de (Galois.linutronix.de. [193.142.43.55])
        by gmr-mx.google.com with ESMTPS id b22-20020a05600c4e1600b00393ead5dc00si328994wmq.2.2022.04.27.06.28.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 27 Apr 2022 06:28:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as permitted sender) client-ip=193.142.43.55;
From: Thomas Gleixner <tglx@linutronix.de>
To: Alexander Potapenko <glider@google.com>, glider@google.com
Cc: Alexander Viro <viro@zeniv.linux.org.uk>, Andrew Morton
 <akpm@linux-foundation.org>, Andrey Konovalov <andreyknvl@google.com>,
 Andy Lutomirski <luto@kernel.org>, Arnd Bergmann <arnd@arndb.de>, Borislav
 Petkov <bp@alien8.de>, Christoph Hellwig <hch@lst.de>, Christoph Lameter
 <cl@linux.com>, David Rientjes <rientjes@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, Greg
 Kroah-Hartman <gregkh@linuxfoundation.org>, Herbert Xu
 <herbert@gondor.apana.org.au>, Ilya Leoshkevich <iii@linux.ibm.com>, Ingo
 Molnar <mingo@redhat.com>, Jens Axboe <axboe@kernel.dk>, Joonsoo Kim
 <iamjoonsoo.kim@lge.com>, Kees Cook <keescook@chromium.org>, Marco Elver
 <elver@google.com>, Mark Rutland <mark.rutland@arm.com>, Matthew Wilcox
 <willy@infradead.org>, "Michael S. Tsirkin" <mst@redhat.com>, Pekka Enberg
 <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, Petr Mladek
 <pmladek@suse.com>, Steven Rostedt <rostedt@goodmis.org>, Vasily Gorbik
 <gor@linux.ibm.com>, Vegard Nossum <vegard.nossum@oracle.com>, Vlastimil
 Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, linux-mm@kvack.org,
 linux-arch@vger.kernel.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH v3 27/46] kmsan: instrumentation.h: add
 instrumentation_begin_with_regs()
In-Reply-To: <20220426164315.625149-28-glider@google.com>
References: <20220426164315.625149-1-glider@google.com>
 <20220426164315.625149-28-glider@google.com>
Date: Wed, 27 Apr 2022 15:28:23 +0200
Message-ID: <87bkwmy7t4.ffs@tglx>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: tglx@linutronix.de
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linutronix.de header.s=2020 header.b=CnD8+0uD;       dkim=neutral
 (no key) header.i=@linutronix.de header.b=mqNvTWF9;       spf=pass
 (google.com: domain of tglx@linutronix.de designates 193.142.43.55 as
 permitted sender) smtp.mailfrom=tglx@linutronix.de;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=linutronix.de
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

On Tue, Apr 26 2022 at 18:42, Alexander Potapenko wrote:
> +void kmsan_instrumentation_begin(struct pt_regs *regs)
> +{
> +	struct kmsan_context_state *state = &kmsan_get_context()->cstate;
> +
> +	if (state)
> +		__memset(state, 0, sizeof(struct kmsan_context_state));

  sizeof(*state) please

> +	if (!kmsan_enabled || !regs)
> +		return;

Why has state to be cleared when kmsan is not enabled and how do you end up
with regs == NULL here?

Thanks,

        tglx

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bkwmy7t4.ffs%40tglx.
