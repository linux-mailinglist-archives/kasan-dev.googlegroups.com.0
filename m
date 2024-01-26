Return-Path: <kasan-dev+bncBCT4XGV33UIBBQUYZSWQMGQEC3UJUYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x637.google.com (mail-pl1-x637.google.com [IPv6:2607:f8b0:4864:20::637])
	by mail.lfdr.de (Postfix) with ESMTPS id 4486483D218
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jan 2024 02:35:00 +0100 (CET)
Received: by mail-pl1-x637.google.com with SMTP id d9443c01a7336-1d73eff3f25sf51814045ad.2
        for <lists+kasan-dev@lfdr.de>; Thu, 25 Jan 2024 17:35:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706232898; cv=pass;
        d=google.com; s=arc-20160816;
        b=cELpaqQjY31q5ZnWg7ZKJSg7lamvngp1MEqaRTKkBvpou0hScYFSMMIkSJyttr7juc
         qbcdk1gl/yLC13LAOkJP0TwyRiEtTHJJgLRAZa70QTXZpiOcZVQxfRaWJDBW6VJTRCwn
         jb8VepFWAJrkCdHEoJHpr1deO/P4qwpDolGjazcgJdnACAwmnSx+5rLuXicitp1ACHb3
         k8UzKcLd8Vn8c0YZOrkZBz58Crfh7TTVLDv6oxtX3LpVVGleBflPuyTcIfFLSUHvXTJL
         ktGD/buHzzkf2LZiklUo72ymiHrxt3o1GvQsIciMc34cpWu2WeqmkOC4gJhdsdw9Hr27
         Pxzw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=aIQy6YCfyHIUKBRlxzEPResGwhbp1pZ9eRZPGLC+AuM=;
        fh=riBrxcA8Qh36tUJKE2+2vGuKFsUK3hAVMFrwnmES8Bw=;
        b=jVlukZt4whv+n7ii7SSs0hwgJHGsX2ofQoSdQIbZD+RCM/zC/19Lbg02EVi009d+PK
         RxZOlhVxEfEQjz9u1KVJ/CwGilx0K5oRnrz1Ze6suNbfkM4OuqwtvsNtL3jC3oKViyeR
         nBImJDXiemgNwO/yWAbEUdL5A103noClZRWTxIWgyOc7sIkVTQbWHzH2+Q4oyabAJ13r
         ixmLOs6k4V8BayW/8FBag09kuMf/ixDb3FWFKEhmGjK+s6jcBDAcDpYfEN0D8h3+aEVP
         4Z9sPlybtTz+xmUOLufQN5zG10BTiLT2pgVb6bJEd+XDeBdR0ULxZ8djBQcnGSW4noCc
         5WDA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IanaUHsb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706232898; x=1706837698; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=aIQy6YCfyHIUKBRlxzEPResGwhbp1pZ9eRZPGLC+AuM=;
        b=FQwI2TrJ4jfO3vAs9e97HOAtBM8Yt9Xk7md3iF62I48i8sOKTI4JFjn2wffOK0lUe6
         q1Xk2CwVDlYBsr+w94WSvGYHEUyYq1IaiVdMM69a7bZkIW1nCdTPc/u7XoRHjXfGuG9y
         0GMgIk9d6qAhaEGd/XSN20UZQIXTcU2hTmk1R6w0B+uC4MaQx806Lc7tcp5Sud5mb6Qo
         wKfJ+xOkblp1YV2ltcRX99WOIX7qamUwXRYuPLcFjtIa7M1pd7yJ/RK3emhtPj4EYfvL
         N5JthqUwK2MRVL+GXOB7Ou3C7b9RZBYB5waoBgY5HAKKJicJ98OvEqmGhZhYsCojhCOI
         v+OA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706232898; x=1706837698;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=aIQy6YCfyHIUKBRlxzEPResGwhbp1pZ9eRZPGLC+AuM=;
        b=E6It94rf7CJgn/kGD8Y37z6D201Q+zK0gjbj60NBlzEaoNfnq8hLPRrsqPj5UD/8vo
         jvmKs0xL+dOSjoSq3UiHYrOu15tHopf1nRSDQVwQqglOfNOdgmrKTY3h2yS1qjcNPXDt
         KlDXO5j2ztR66Z2T5tOCyyylkJck9az27Ie3XV7uwco3BAYXypGy/nyaqGzn2QcidbTZ
         N60cI2VZ7i4l/9EuJt1GTw9sUvHH90kNNhlPiL0Kt/lec0A5E5mEecFW9SAnolY7XAyd
         49rdo6yUQOUTlzDWtatP6TBNrgF4xJDSuduOl7/WFyTmlc2ebxpDhoBPign53IFX0nG3
         oPRg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxkO4fQ5k98uVAdT14qwAp5Y8QURVO+t0Ksc7QqnwkqisAFRMSg
	DwpsFau/oU03Ky/I6ecgSruArExvul7u37EAhO56QtY5S3v6yqhn
X-Google-Smtp-Source: AGHT+IF8x7VbP5Hw7Fk7iCY7WL++AiOQsWeaA3XsYmv4cZSFzELMm5HKo0DY9zq6Z5QdrJtujRIiRQ==
X-Received: by 2002:a17:902:ec82:b0:1d8:94b6:65e with SMTP id x2-20020a170902ec8200b001d894b6065emr805891plg.2.1706232898501;
        Thu, 25 Jan 2024 17:34:58 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:bd86:b0:1d7:3250:4126 with SMTP id
 q6-20020a170902bd8600b001d732504126ls160823pls.2.-pod-prod-08-us; Thu, 25 Jan
 2024 17:34:57 -0800 (PST)
X-Received: by 2002:a17:903:25d1:b0:1d6:6b13:4f46 with SMTP id jc17-20020a17090325d100b001d66b134f46mr572121plb.66.1706232897193;
        Thu, 25 Jan 2024 17:34:57 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706232897; cv=none;
        d=google.com; s=arc-20160816;
        b=V3Opyw8LHCDftSrDnhclYu5LxIVFE1qWdJaUoU/zyG9hmoP8CeI9bIk1xWRtupVXTu
         CL+h1UZXtt9qXw7S5ono5euaXBUmlyCFsrdqATdWnmBoNC5ygJ4TPbKi1fMKa8ScP8JO
         gCkfNfUCmOwTBzDHLT3f/UuWzZ+yACPxO+cfKg8d+Xx9oiyWaoJWUhZbDgcpE3A6iRDz
         oloBdx7/pMo25PmACQf9neTjEGGobPZOQJ27rDMOSt1WT0K5B08gGf870Fv8WRbCtXtK
         ufOyuEycFQlmbhsqjNxWwe1bepN4C/7iREfffPEIbmlDpuAePkHNaT2ppO0Z9Uc99xmS
         3cwA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=BOnTIPkHjKHeZptNyEKK6utwNyJxAgnqgtWJh28DSoY=;
        fh=riBrxcA8Qh36tUJKE2+2vGuKFsUK3hAVMFrwnmES8Bw=;
        b=EUZaZHVU+/lz8M9KbiBuUilLaZvj6xGOqVH81Ni2sjL9GZ/kPCQhWXiDzRvYEjzNGA
         +rupFNzK4POQNF2eDPODExGpONZa31Sn6tj1JEW43oxl6jguJYlG4jO+fz7Ms3/BCXH7
         tPY4MzTf9j2u9gZNXH3nPv/1xEQWHuaOPvacaCWjuDuyNJaFde9H/KupH6a3UgUFO21D
         Qg24SmUfiPvIPck5muE6pd6At0ZU1rZeJnFpHlgPlsTwgKENGtO7gVWTIHKgvLbsuFEI
         YHKP2KIf1BXtKSNwfTG/YOxEDZahnhxtrAj4PvS/flSSZ0G9m5v9xK/LikGOhxGaDBcI
         fnRw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=IanaUHsb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id m19-20020a170902f21300b001d78a422ab1si14540plc.0.2024.01.25.17.34.57
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 25 Jan 2024 17:34:57 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 723AA622C6;
	Fri, 26 Jan 2024 01:34:56 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 963F9C433F1;
	Fri, 26 Jan 2024 01:34:53 +0000 (UTC)
Date: Thu, 25 Jan 2024 17:34:48 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Alexander Potapenko <glider@google.com>
Cc: linux-kernel@vger.kernel.org, linux-mm@kvack.org,
 kasan-dev@googlegroups.com, Marco Elver <elver@google.com>, Dmitry Vyukov
 <dvyukov@google.com>, Ilya Leoshkevich <iii@linux.ibm.com>, Nicholas
 Miehlbradt <nicholas@linux.ibm.com>
Subject: Re: [PATCH v2] mm: kmsan: remove runtime checks from
 kmsan_unpoison_memory()
Message-Id: <20240125173448.e866d84cda146145cbc67c93@linux-foundation.org>
In-Reply-To: <20240124173134.1165747-1-glider@google.com>
References: <20240124173134.1165747-1-glider@google.com>
X-Mailer: Sylpheed 3.8.0beta1 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=IanaUHsb;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 139.178.84.217 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Wed, 24 Jan 2024 18:31:34 +0100 Alexander Potapenko <glider@google.com> wrote:

> Similarly to what's been done in commit ff444efbbb9be ("kmsan: allow

I make that 85716a80c16d.

> using __msan_instrument_asm_store() inside runtime"), it should be safe
> to call kmsan_unpoison_memory() from within the runtime, as it does not
> allocate memory or take locks. Remove the redundant runtime checks.
> 
> This should fix false positives seen with CONFIG_DEBUG_LIST=y when
> the non-instrumented lib/stackdepot.c failed to unpoison the memory
> chunks later checked by the instrumented lib/list_debug.c
> 
> Also replace the implementation of kmsan_unpoison_entry_regs() with
> a call to kmsan_unpoison_memory().
> 

"false positives" sound unpleasant.  Should this fix be backported into
earlier kernels?  And can we identify a suitable Fixes: target?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240125173448.e866d84cda146145cbc67c93%40linux-foundation.org.
