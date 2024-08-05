Return-Path: <kasan-dev+bncBC5OTC6XTQGRBDERYG2QMGQE6TXOXIA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3b.google.com (mail-yb1-xb3b.google.com [IPv6:2607:f8b0:4864:20::b3b])
	by mail.lfdr.de (Postfix) with ESMTPS id BA8539473ED
	for <lists+kasan-dev@lfdr.de>; Mon,  5 Aug 2024 05:35:41 +0200 (CEST)
Received: by mail-yb1-xb3b.google.com with SMTP id 3f1490d57ef6-e0b7922ed63sf14862244276.0
        for <lists+kasan-dev@lfdr.de>; Sun, 04 Aug 2024 20:35:41 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722828940; cv=pass;
        d=google.com; s=arc-20160816;
        b=HPOcthI4IF2SZhE2Dl0NF5S+ySxgeOYMssznkHFFSNBRgzSVG8/e64a8KioVNx3kqi
         qdRLU/+e6J5VwUTOo4ylDOhKRgtKBJSG+00mq+lTREkMnKZWtoCSDMJRPswQCFYztOt8
         AmmsDFXekBlVSir9zP1F6ZQE/24ug6V3SzvGWoOFQyixPDRG2UplHaDK5dayiOZMxAKX
         TuCHCxExKFK9fifzBlTmb+JomSTY8Z1Dvk3M/QXk448pqbJFCv9lFEqzzrLVMjCWC329
         SsELkryIPpmxFdFnM64JHhXI8CU75V9OBkOEVgnneZTTjfqyORDz6a1dEIsz9yyNNYZU
         w2Kg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature:dkim-signature;
        bh=ytWxUKZimS2NhMcVqXiyu2ljK2bAiYC0e5SMHIQGvcY=;
        fh=HNw/YWgIv4ClaHGCQj8z7lZYfpE390HECD08lsbNlQU=;
        b=YTqlqCiLD3oV9NJNm4HetKx+ca/X8FPH6WCqm7T/4aY2CnfpVsukaVnH16zGDAQEX9
         m861EPOY8DIKKxRTg3n6Bt5odYUbRg9r/KJdT22odx8MjL9RkXEdWTtihviF6Nf2U18T
         +PLq/WzSvBNOMZ5nJWk7KYpF1ZWHgDmQ8aHHFGaZDZ0UQf0piQ5LuFCHtu/PKsCTM/r7
         PH1eg0ApAOn+vX/ss5UOvhuubDRRpjc5FZlcOgVZRFT8i6EHJ5s2YfsjNeHDW6cVolnR
         l7i8f9Vkn7SQcrYl8rK5ozg6l73XYTpf1pg0EDUeMgbNZLij6iVek5aKsGc7abwq4/MF
         e36A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AmwA4Odc;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722828940; x=1723433740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ytWxUKZimS2NhMcVqXiyu2ljK2bAiYC0e5SMHIQGvcY=;
        b=RHEg+yVlLasXopEzkDSVSZu71PyNudS3xJzT20hK1nXYh9wsx/VPWayWi2mU2osxo/
         wxi9LrjvUn09Fg7cBdaz8iEgcSGMsbYSpKWTxojfWwP9kMdBvhq3t6ssAssZuGPcmK38
         /71al6wT0hzk48EZRdICdl+28078qTl15qRGKZjYE88+PFDAtJJnhYMCfOAhaZyvkSNT
         fYwem03JZBprDj3cZbFcrVoNm3jzXEwOS42vI5PqehaAfdYKGEBPU9MJviBwC58U1KBf
         s/oYiUOu+LMk4EurBay32NvcxpYmToaThu19Z+mHlTNu/fmx4r9Pki2nJBQ3gJv4/Oo0
         pvfA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1722828940; x=1723433740; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:from:to:cc:subject
         :date:message-id:reply-to;
        bh=ytWxUKZimS2NhMcVqXiyu2ljK2bAiYC0e5SMHIQGvcY=;
        b=XU6BIFDBAHd+xYtHEhKN/zyc+IC2LRThQlcqsjrKBd9bhFbm9cN17VfHcIH6hatPtF
         dxhSL8qQ7woe8PjvfuMy6HJ7bwxdahEDrA5qExm31IwIPaLLxL69J+VMkU3FFMEw+cby
         yHDo6zWzt67aK1En7qGXqgTTSsEg08quyyjLRiy9YefxJwE3LQAjsNjjPk2p95/aX1ez
         iDYnfmcuUHXXhujlBoLvpcHGV9lT5jakqmhWQmZOQHoOElAwIIRvf09chzn5fbf1zpbm
         cqsRU92spDOYon/uoccH/tUs2HrAspN8TSb0lHnmkuyuw9PdIceuhktYoFEeKWe6V8X4
         vN+g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722828940; x=1723433740;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ytWxUKZimS2NhMcVqXiyu2ljK2bAiYC0e5SMHIQGvcY=;
        b=Vv8kFzgwxFR5n0XCbPSrXHyS3MF8nQmTiSof7ZeVilQDl7o/1fIUcvPDamPYEa6Vyx
         EYFBM4nJ9pxDNBUszH99SsD6VqAfTx8ekfqlCmXP/iv7RS4EREIunvirCyoCHSVJSag4
         247LrghjM9oy5iECIlwn8nLZ9Uh3xb8DIvEGBQb9J5GjD20GJuhrwY+0HHrzMTjTMFTe
         X46kMKY9GdouB5QGaFEtjJ/cxg3tGFeSXvhB1dnrvmlNArl6oIAT7URZ75rqzXX3CoWm
         weQdYCW8YClI2gumMnN4rtEBy/eREJOEKvDtCKvasd+VrK/k55TZHG2qV1QO1WBqL2JC
         ut6g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBlh9Cl/e2JIMfiGj6fNqhOvxeTrco096552ZKy3YDzRKc21VqtK3hzjzTnZYWRdqVrlRcnMysLi7O7BRhiaC8XGci9dD4vg==
X-Gm-Message-State: AOJu0YwzYMpFZPMZYczlM9gcltfjSMU+Q1KFL9+L/SkrTgfr4YLAnMDb
	/v0ypmdiPsE0ni7oF5qnxPPUE8rdIpD5xgWMDmBttHl4Mt7sovHd
X-Google-Smtp-Source: AGHT+IE1y8bFcEtjR9pMGKhlp7g5KeNqkod8lCHvUH/KApviZKVh3RJPR/cRAGE+ltK1DB+mp75Xbw==
X-Received: by 2002:a5b:eca:0:b0:e03:3f0f:a643 with SMTP id 3f1490d57ef6-e0bde50cbddmr9805979276.50.1722828940399;
        Sun, 04 Aug 2024 20:35:40 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6902:1003:b0:e0b:e5b2:98ba with SMTP id
 3f1490d57ef6-e0bf49cad5els2593125276.0.-pod-prod-04-us; Sun, 04 Aug 2024
 20:35:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXyD1CDV1z55+IduQ5VVP8iMlguoYcRUfHsxZ6LeWzwHIYT+bIONUeVJ7li5i2AvSq54ZbNiO3NQ3tTTPYIwL72D4han4fi896ZCg==
X-Received: by 2002:a05:6902:2b90:b0:e08:9024:c028 with SMTP id 3f1490d57ef6-e0bde50b342mr14200732276.48.1722828939497;
        Sun, 04 Aug 2024 20:35:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722828939; cv=none;
        d=google.com; s=arc-20160816;
        b=GmOY9j2BYzKCuGB4YvwIEGKIEIUzJxlTcVDbuVb26hti0hcj3hllpnCopU68y35YEC
         UW6WjkdrR3eMro+htGlngePzjHp9bUwpG1izDNWHNO7S0E4begCmG1xoVVJiD0otMgCx
         v8labuLQ3DoZFmV3JmRpKgao7z+G3lilUaAA7y4Gqhm6lwVqgPimbvh8OaBCchUXRnCW
         VvctRsMok7Po0NgYZKqeHCvsdHgVzeKWOGfYKgITUJjy68+exnyJDuoK3bFYuyAfLrII
         P/fjHkKELjblRsPHxZiPSQRUYsIA0u3oXPK6LIkuant11A46j62o340qXUZ+ocgN59Zm
         2q9Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=0gLtqxxJQQL5ckpGj5N/lb9KPTO94eZK4kflR9Rxq9g=;
        fh=7HQ3b3z3LAYJCOLRNDWEmGjyISvH2m1ojjM/t7RnY5k=;
        b=EWWneK57E4PVdll69upI0NfW3Z5maboL4Ef9zJSqB5gpD/FqUkjkm/r/Zqimf+nW9G
         CyrgxmkIdjOKOQHbeym6GyQIdQpzEuLCAQ1f4T7japt8XsQB/yLQVYXvyW5UOMFEuJlM
         1NUJ7076hMx/XVf6rwOt2mCqCPVYmTikbDRHUUczsjceR+v0TUe6J81VLg7edwZyLbM0
         LfhHhQOaCvIKlaNUN1NKGToijnAtRY+P2SoLZaG/Lv/Zx66HZZZbsBdwnV2u4mDIc4xZ
         r4AZwQt6I/Ume8ZwpC4Ud6xGI1k3ARhQG70KTA1MiGHyPDgvUEK3saPhf+5S8+6z0Phv
         f4Ig==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=AmwA4Odc;
       spf=pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x631.google.com (mail-pl1-x631.google.com. [2607:f8b0:4864:20::631])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-4518a57dd5esi3043771cf.0.2024.08.04.20.35.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 04 Aug 2024 20:35:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::631 as permitted sender) client-ip=2607:f8b0:4864:20::631;
Received: by mail-pl1-x631.google.com with SMTP id d9443c01a7336-1fc4fccdd78so72737895ad.2
        for <kasan-dev@googlegroups.com>; Sun, 04 Aug 2024 20:35:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUzIit8iiHAByB0buRAOQjYFZ+Ue/0sd1onROLyrNdScbZL1m4/XTvnhbMGPpqKIRLbPbERDtSZgwfZojx2ddAEgN+6lvL3l5owGA==
X-Received: by 2002:a17:902:f54b:b0:1fb:5d9e:22ab with SMTP id d9443c01a7336-1ff572b960bmr96655475ad.22.1722828938387;
        Sun, 04 Aug 2024 20:35:38 -0700 (PDT)
Received: from localhost ([107.155.12.245])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-1ff58f19ca6sm57003345ad.49.2024.08.04.20.35.37
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 04 Aug 2024 20:35:38 -0700 (PDT)
Date: Mon, 5 Aug 2024 11:35:34 +0800
From: chenqiwu <qiwuchen55@gmail.com>
To: Marco Elver <elver@google.com>
Cc: glider@google.com, dvyukov@google.com, akpm@linux-foundation.org,
	kasan-dev@googlegroups.com, linux-mm@kvack.org
Subject: Re: [PATCH] mm: kfence: print the age time for alloacted objectes to
 trace memleak
Message-ID: <20240805033534.GA15091@rlk>
References: <20240803133608.2124-1-chenqiwu@xiaomi.com>
 <CANpmjNNf8n=x+TnsSQ=kDMpDmmFevYdLrB2R0WMtZiirAUX=JA@mail.gmail.com>
 <20240804034607.GA11291@rlk>
 <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <CANpmjNPN7yeD-x_m+nt_bsL0Cczg4RnoRWGxPKqg-N5GdmBjZA@mail.gmail.com>
X-Original-Sender: qiwuchen55@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=AmwA4Odc;       spf=pass
 (google.com: domain of qiwuchen55@gmail.com designates 2607:f8b0:4864:20::631
 as permitted sender) smtp.mailfrom=qiwuchen55@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Sun, Aug 04, 2024 at 10:37:43AM +0200, Marco Elver wrote:
> 
> Well, what I'm saying, having this info also for FREED objects on the
> free stack can be useful in some debugging scenarios when you get a
> use-after-free, and you want to know the elapsed time since the free
> happened. I have done this calculation manually before, which is why I
> suggested it. Maybe it's not useful for you for finding leaks, but
> that's just one usecase.
>
Agreed with your concern scenarios.
How about the following change with additonal object state info?

+       u64 interval_nsec = local_clock() - meta->alloc_track.ts_nsec;
+       unsigned long rem_interval_nsec = do_div(interval_nsec, NSEC_PER_SEC);

        /* Timestamp matches printk timestamp format. */
-       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus:\n",
+       seq_con_printf(seq, "%s by task %d on cpu %d at %lu.%06lus (%lu.%06lus ago) for %s object:\n",
                       show_alloc ? "allocated" : "freed", track->pid,
-                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000);
+                      track->cpu, (unsigned long)ts_sec, rem_nsec / 1000,
+                      (unsigned long)interval_nsec, rem_interval_nsec / 1000,
+                      meta->state == KFENCE_OBJECT_ALLOCATED? "allocated" : "freed");

In this way, we can find leaks by grep "allocated object" and inspect the elapsed time of
use-after-free by grep "freed object".

Thanks
Qiwu

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240805033534.GA15091%40rlk.
