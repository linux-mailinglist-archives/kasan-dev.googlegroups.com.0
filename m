Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6HMYG2QMGQEVP7GIJY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 94DDD947596
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 08:51:38 +0200 (CEST)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-1fb44af00edsf11299365ad.0
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Aug 2024 23:51:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722840697; cv=pass;
        d=google.com; s=arc-20240605;
        b=a59iTdWGfRLq4ADWTvmGOxI8RM9BoaHZ3SlHgq5GtBA6li6Vl8ejGLRx8MDftpmrPh
         DBIitWA2TZsWhFZDfmnOCy3LAw/U4hKhSwnF4SU+De7HCyyGomVJpf+bMPlr8RMhY896
         s9gwIv7098FWs3V3W3BdpXadkMlQbIN6ngTO83LbC6PxDY/z7VcMJ5nflEbz7ogof0KB
         WNiwsLaW9EaE8fP/UKSLe43HpKkPJUI7chSb7x7Rx+UwjUd/9vxdatVZ3Tj5BHRAuDVc
         7XtYIZaYkiip57VItHajcTxRnBS0pJ0Ye83yZmuAzsPr0Irc9D6TkHv0U+iNbaxs1dJu
         EeIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=OYJ2Pl6vQjgXAvjDYMjGxc/WqAjGEDhYK7MlXiHwtKY=;
        fh=AKuSPMY/ijBGAj2fG9PnlSFMDbgqczbN+ouE5vcbS1E=;
        b=YYfP+zzI6YJH2Yp5d4ciX2cIx5AMGe9UzGIgZ+dumMl4X9UEEKZr1Zaiwrnr5BDo+M
         BagfYTWjousZKOvq+Bt2sG69r8kkRIhpY26pTjYvh9mVp8CBxNIh497AEqvseYzyWr8K
         trRIaqLVj2OqtPdrkFuw/9NjHxBkoRqtnWhMhBBw0fdbOVi8IeWkzdc/e7TwhAxkqvmZ
         K1dIy63wMJ/XNULKJbxRVBqj1Bz3SJj72GmFgbx7kS4vFN2LmKZRKOF+NMIlCjvNTHVT
         UjMCzE0/tKxEweDJ8R+kyT1I0HKC/EE3eTXRT+Af9u+huW1tFlDcX0/zAivs9QL5i3ME
         J/5w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vX6usHAL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722840697; x=1723445497; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=OYJ2Pl6vQjgXAvjDYMjGxc/WqAjGEDhYK7MlXiHwtKY=;
        b=u9S9UGarkFucAh//TGHvnYMiJXMj/N0RbVlmLP0Lex11j5yzvMGDFq8cL3wGraF1h0
         49rpX2e/KvsCaM+bC9DfeaBZd+IKi9j3sGvaQ3yrauYI+rEF2bamqj16p0SlVyUomE2B
         fbtMuK2APZIeWajDfXMDjhPJgNwLhhch3VEcPi+oO1j3M7+qo4EVhz0ypi8ggOaqj9dS
         NNG1aVmD8qbcv0Kr7ohsZbtjES3+tytp1T0eQfTGLO/6KYiO4xmK4tj0Dk6m07zx4Jvr
         w28f/JWcMYKUHy80mkYbvR0kdp6gfML/hvZf8mWhiZn7Zbr4+uBEMms02JQmex98Lb+3
         EoWg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722840697; x=1723445497;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=OYJ2Pl6vQjgXAvjDYMjGxc/WqAjGEDhYK7MlXiHwtKY=;
        b=SPZUIkWCseOWzmAzy2MQDl1sU4+k3PyWlXAtqItkjMD1RPrr0OcvZaMf5rMEPZx5lm
         5/7ecK75dX9KLTe5qhWT5nxrXBmYyXqSav3bV/a5omyXD7RdyWYTVTHeH8lVtFAdue4z
         2fdswwm9xa1s9qPCBsQv2BVQ9M0eAvOrPs3MlzKjpMWou+bDatsLuxTWzkibK4cVp2Ny
         9HwDk6l6wSJQgTgyj11EtPNeHGqtCNuLfTYP6uibte+l9RjhK3++g9X224Q66AqRSmB/
         f+RxCuqQJhE7b00FY/QUIUJWAQ0ViQ+YssE9XF+1LojyZhFbL68CWPaCLYI8tpE7Vbtv
         sehg==
X-Forwarded-Encrypted: i=2; AJvYcCXavjcgwe8gL/0kbrKY8X60IRldHtSgKW03eKfAhPcky7M4IlfpoARuoabpJUnr6/Sqf3zPjaLWZRb7ImwZDY2Ur6rLoi1zjQ==
X-Gm-Message-State: AOJu0YzGXz6Tq7yfPdi/nopKMvKLE1APjlVcHxDo/tlnmoTHT1F4bWf7
	0eQ4oRCWx8uFxNHSYS1oKTDTK81elOEX/k1Nn2khFKT8NhuoGr04
X-Google-Smtp-Source: AGHT+IFgg67j5zdAnVwlS6yktNuHHqe/CP0vOK5IyQdkawnV13DVt5JI3vLskZQ+Tw9YwnTG57xkDg==
X-Received: by 2002:a17:903:1c5:b0:1ff:3b0f:d61d with SMTP id d9443c01a7336-1ff6b30bef2mr3486855ad.24.1722840696525;
        Sun, 04 Aug 2024 23:51:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:8d01:b0:2cb:4a85:9588 with SMTP id
 98e67ed59e1d1-2d00d1c4fbfls1378055a91.1.-pod-prod-03-us; Sun, 04 Aug 2024
 23:51:35 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWCJdbFwzmJ+GqGTKlTJp6UKNbpUTA1KZ3EqNX8NRYZ1IoPzFJzHWUTBOJe8EC+xxwdkxCmvcyTccY6YS9GsuhzaLg4BY9t1BePZw==
X-Received: by 2002:a17:90b:1dcb:b0:2c9:83f3:1291 with SMTP id 98e67ed59e1d1-2cff9524456mr12429106a91.34.1722840694905;
        Sun, 04 Aug 2024 23:51:34 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722840694; cv=none;
        d=google.com; s=arc-20160816;
        b=fyT1y75f1JypMYStgJ8dUT/2zoVAtSHdi6uen4sdDogNTGQkY4AE/23J6m7PKuOMRz
         +HGD9A01hcW+CSZqze/bKFs9G9W61TTWL6SUS4hC+Rt+LDFMA6KgFUArwfri0T1i5V0+
         K07cL2xx0C3ENdMikIzOkrSnjfxy1eEOXASjHy0G8g+Nq8fBz5XaBD8GI4oi7d8ibJE7
         ZYjRxOWTejHAyA0OVerz7ZYavvcBp9fT5HlrCu0AFg43HvFQcio8rxb2HZT+oFVMiG2y
         n9iBTbieW9dm2cFxDVszs1enchw9Qd36GF3TK+KYuqlPfuPFCJ1GjE9i6ZozXQZvifyV
         mRMQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IUBNG1lIyvhInWPDctmqLdJ8JkiVZzYt8STEbPyqNN4=;
        fh=VGog/2aWSAuPomJZGKQAgkSUp5BqmfDcUWdI0PieVrU=;
        b=YZyJrELHsYbnODx0RW4BE60bC5qIWYX0PsQILYraVQ3VK8iwvW+8qzkPRv+/Otjqqh
         Fr+LeJvApQzEduFw+cAhw7bFRj317pIJAxU/MkDeBcniOKKOb9+JOiHLTRJ+KUQ3s8ao
         7PWJiY85LUNOr/jOn/X9eun5qj1imJf8GE3zhnOlkN5/kEcQKPAy8ysV4uf6rkGW3YbB
         gaTQbA1zVwZ1Vl+TFzUpKKmIxxiRcTF6hAus0iNRnLPAH9nUOymX/m3QUx7W+UboKWvc
         DP1orh7uKzMe/1qwDUMSiIpmiqcFhrcYmUOEai7GjHGlzswDNwPkeT4QlwB1VsYpeZEv
         3Fww==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=vX6usHAL;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ua1-x92c.google.com (mail-ua1-x92c.google.com. [2607:f8b0:4864:20::92c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2cfca1da81dsi1038382a91.0.2024.08.04.23.51.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 04 Aug 2024 23:51:34 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as permitted sender) client-ip=2607:f8b0:4864:20::92c;
Received: by mail-ua1-x92c.google.com with SMTP id a1e0cc1a2514c-825eaedff30so1985602241.0
        for <kasan-dev@googlegroups.com>; Sun, 04 Aug 2024 23:51:34 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWTSfSfDU1wULaCxJBEw8unpEGh94aL95/ue9kNEblXbU7YRLYyj+UyyoEcvXDWFo8i3KtqkFdRDB7YDQfPQmZotrBaki/kE76k2w==
X-Received: by 2002:a05:6122:4692:b0:4ec:f6f2:f1cd with SMTP id
 71dfb90a1353d-4f8a00189b6mr8430275e0c.9.1722840693506; Sun, 04 Aug 2024
 23:51:33 -0700 (PDT)
MIME-Version: 1.0
References: <20240803133608.2124-1-chenqiwu@xiaomi.com> <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk> <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
 <20240805033534.GA15091@rlk>
In-Reply-To: <20240805033534.GA15091@rlk>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 5 Aug 2024 08:50:57 +0200
Message-ID: <CANpmjNPEo=9x1FewrZYNG+YEK_XiX5gx8XNKjD9+bw7XWBV9Xw@mail.gmail.com>
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
To: chenqiwu <qiwuchen55@gmail.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=vX6usHAL;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::92c as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
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

On Mon, 5 Aug 2024 at 05:35, chenqiwu <qiwuchen55@gmail.com> wrote:
>
> On Sun, Aug 04, 2024 at 10:37:43AM +0200, Marco Elver wrote:
> >
> > Well, what I'm saying, having this info also for FREED objects on the
> > free stack can be useful in some debugging scenarios when you get a
> > use-after-free, and you want to know the elapsed time since the free
> > happened. I have done this calculation manually before, which is why I
> > suggested it. Maybe it's not useful for you for finding leaks, but
> > that's just one usecase.
> >
> Agreed with your concern scenarios.
> How about the following change with additonal object state info?
>
> +       u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
> +       unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);
>
>         /* Timestamp matches printk timestamp format. */
> -       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
> +       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago) for %s object:\n",
>                        show_alloc ? "allocated" : "freed", track->pid,
> -                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
> +                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
> +                      (unsigned long)interval_nsec, rem_interval_nsec / 1000,
> +                      meta->state == KFENCE_OBJECT_ALLOCATED? "allocated" : "freed");
>
> In this way, we can find leaks by grep "allocated object" and inspect the elapsed time of
> use-after-free by grep "freed object".

The "allocated/freed" info is superfluous, as freed objects will have
a free stack.

Consider a slightly better script vs. just using grep.
/sys/kernel/debug/kfence/objects is of secondary concern and was added
primarily as a debugging aid for KFENCE developers. We never thought
it could be used to look for leaks, but good you found another use for
it. ;-)
The priority is to keep regular error reports generated by KFENCE
readable. Adding this "allocated/freed" info just makes the line
longer and is not useful.

I'm happy with the "(%lu.%06lus ago)" part alone.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPEo%3D9x1FewrZYNG%2BYEK_XiX5gx8XNKjD9%2Bbw7XWBV9Xw%40mail.gmail.com.
