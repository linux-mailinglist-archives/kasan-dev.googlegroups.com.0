Return-Path: <kasan-dev+bncBC7OBJGL2MHBBW6D6GXAMGQEY3XOCVI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43f.google.com (mail-pf1-x43f.google.com [IPv6:2607:f8b0:4864:20::43f])
	by mail.lfdr.de (Postfix) with ESMTPS id DCD6D866FC1
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 11:03:09 +0100 (CET)
Received: by mail-pf1-x43f.google.com with SMTP id d2e1a72fcca58-6e52e3fdbdcsf332943b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Feb 2024 02:03:09 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1708941788; cv=pass;
        d=google.com; s=arc-20160816;
        b=smGwTkGIg5GfjmPLWqBR0VRzoXo2Zk79WK/gB9Pau0CLTkp8T2rYy1Z9RFN6WLTRLH
         V8V3iLogpUDiKdO0Tthi7MoRfZBf9ZjB/bQED03xdimryNqXAGdmR/r7pw+VIKzmCb0H
         0kWRzGxQZv2j1ICNTaUVo0673FshLDXUoWu1VxJBn6MjYsZzmzPvGOQ4NE2A7lzDAYnH
         2Sr9yMFGveIDK4CQCA09cT9P+2ZdTWdXtAVx+1bBJpV59wdp8D/a+H2i3tBdPx5Aflwj
         FPTYty4rl1rerQZcgXKENWGcK9mmARKJ1VA2lXpDfZYxkN7FIqeef86ao59y8ktznACR
         diGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=Iz3Vwhkf/kYDQDPlI1J3GUYqqIfJzG2MBg2+hDi0Yf8=;
        fh=qgkeoZQN412Rybii8QO5Hb9W/biUJxHmGf2FRqrPeZg=;
        b=OYGRVJJJaoQOckjSvL6qDsVzIvukGfhIPO/ANPvicK1+qK03BAzFSAsGrVTp0+dzn6
         phg+lgqJIpk1ObkSuDeXKA1lLMVkmGaMGWSkawLw92UH4ao/9+atTfmmmwZHOTsX0K/a
         WRIvQEG7LokWpfb8u9flL2gpAXXPTRAg53FGmRbSBIsyysSgQV7F607jyF/kvOryELXU
         s2hk2xlimLDDCHYdfJkv/Ft4iG4BxbCDuFW9JFm56AiMbqGBqguwnRUFviE4KDWxRu2K
         srsIwi0K+OOIfPSy7x2vjyJVAEnKzyl4dvxB7wXFAeMqgtFUri9GpE/QsBCxCTm0CZFb
         39EQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rOxakaS3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1708941788; x=1709546588; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=Iz3Vwhkf/kYDQDPlI1J3GUYqqIfJzG2MBg2+hDi0Yf8=;
        b=YawoUoAlNpkJJZDaDJs2ZI44/7nJIoS2688r3fxFQZyOcoltk2pn60coedIHG+/bNt
         ZWypEV7462O6HAoZmOa0d842iDv4cZH5tpTP5nOIjemN2e82a0Rj2vKbTdspW8mT7reE
         6U0AnwTFOAwpy/dNp6QY4dFvpmKvEHYYgvqPg+4AC/pdmbSGmoITw/djS3OUSooGF35l
         HiGi541MEzU7VD2KBWLI96SKToqN7kTBhUWWskavuk1Mn+7d9tVbzEQpI6FM14GQgLLk
         IeF9Xm6kXja3OaJNMcBzkbNF+ihUEf20TDScKe8Ya3vUAhjL/m2ZhOfOQVL6VPM6v/AE
         gSNw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1708941788; x=1709546588;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Iz3Vwhkf/kYDQDPlI1J3GUYqqIfJzG2MBg2+hDi0Yf8=;
        b=CDFbnDfgba+kVP2fgIP74vWnYCznbNBpjvQG7V4LPu5EMChLtnhZM7UloC5LXhtV51
         KPHKcll2xuScROUWXNEV7BhkAi+iqHwJICNInxMhK6899gD2voml2sUtfX6SWJp9OIcj
         3rwcLWPcFp5r+3IEC1Q14rJOkc6305Xz8lWgoasQtY4O9+IbVPVNI5Qp4JzXodgzpcCa
         xcrdq6dRNgk7XeN2OIbQMOWly4rRwxGbDsXXNwtA9F/+klWg2JGEeMchIwoSUXxNLhJ9
         8sjRVg32J3rFUeKfrsBYOs4F59KLDUnl5uHWimmiFEo/vyAVz6wlRcEddtYOahL8K3Dt
         fP7A==
X-Forwarded-Encrypted: i=2; AJvYcCXkxCuc9k15sIaPWYXkc/8aknxWJKPx+ESAoMOemjsNOr2XpLJGzHVyYvboasSWyeXxTQcmtZhaHdWdjO0+uE+eT9o/nbpxug==
X-Gm-Message-State: AOJu0YzUXWG+ATCU9rHuqfOSIBT9sZ15JMK2zHnq2iI1COMJ3eeoaDrv
	OsrpeUSqJ61xnvKRf9b9aHqH/m876piQ8BO7IdMmzXR5PD6MkBn3
X-Google-Smtp-Source: AGHT+IEoIBiirB1gEwNBUksy0ndPfpkSPya/jdbPc8Mpewn/4xFgS4iVqk18pdpZR8mrplowUTxWQA==
X-Received: by 2002:a62:bd19:0:b0:6e5:d6:134a with SMTP id a25-20020a62bd19000000b006e500d6134amr3673078pff.14.1708941788101;
        Mon, 26 Feb 2024 02:03:08 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:800d:b0:6e4:68a5:b0e9 with SMTP id
 eg13-20020a056a00800d00b006e468a5b0e9ls1905467pfb.1.-pod-prod-01-us; Mon, 26
 Feb 2024 02:03:06 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXkyT8NNqVIdV1O4Ngc/mku2us0M8CZf7hIyoPAdLh462gXr7JQmds1KOVi+sDhu0GG54vHXBEmNmxnmLINmUvrpux/eqNTHZylIw==
X-Received: by 2002:a05:6a20:6f8e:b0:1a0:8a2b:542b with SMTP id gv14-20020a056a206f8e00b001a08a2b542bmr5786374pzb.16.1708941786103;
        Mon, 26 Feb 2024 02:03:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1708941786; cv=none;
        d=google.com; s=arc-20160816;
        b=mUYr94dIrC/Qa/ehFmULTHqzSUHeS7cYb3OayCEZ2mmIBen+d4ppp5W9FCKtuLM7qS
         aI3nysmBSIr1CqZj/Cbi1OOw8hpI7usAiynhBL/HvSAyqi2Ol8CBfNt4iJ/IZIvDUhlg
         TXyzHu+KrB/F8KsJksH9qwpy371fSqkgRCz2kH1Kt6qkRSuTEZq35KXVYbswwKkbAPTo
         u6tX2gpJL+9SIO8GXxy/t3ZE3e1zd+q6lKbhQVZf1833FuZ51LCY5gkSfFdflvyGWsWb
         KhZ/euu6t8qAuY6Ck5l0zfzeSkV/GsKJyw5QNv49TU1ezWlQPDUT5mSSdq/Us6pln0zZ
         87Rw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=1ReaxqDHa24p0YNicQdRdk100wLLbR32pRNljWJdCTI=;
        fh=vUlCHA/27Ge8ciuPDfO3SuakG9BZJTijpAzuOK2LkNc=;
        b=qno8R2OI1ggF+HWnKdgv87OScK0ffdnJIgZO4hZU78soh38gEG28CkT9A6OU16TMZF
         VCsJdjL4Mr4kRq+NDnPuC70hrWiZ5BFpxtQwmcNMHTyzn1LkmlGM/4ekD2cZb782J9rs
         MwWIm3ZQro5ndlNIodYWbGarB8MGTBtG7c8Qm20Cq0MNU3i1jVzLOVVwgpb2x87JWKQh
         d1Qs4qyB6yguy/KpcyuCRrn70lOYNx7HGsicErXbjtWlhlWQK8Qs3ceEPEhQLA9Hv8qG
         5VaJHwNockxgQQS1bT3fowkaKpf+s07Gi1MGhxOoAXCTQOqmKIM5j4SHg1dzuDKfRzhJ
         I01w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=rOxakaS3;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe36.google.com (mail-vs1-xe36.google.com. [2607:f8b0:4864:20::e36])
        by gmr-mx.google.com with ESMTPS id w14-20020a17090a8a0e00b0029aca41e2f4si98468pjn.3.2024.02.26.02.03.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Feb 2024 02:03:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as permitted sender) client-ip=2607:f8b0:4864:20::e36;
Received: by mail-vs1-xe36.google.com with SMTP id ada2fe7eead31-46d60c75683so267148137.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Feb 2024 02:03:06 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCVuh0947Z9+7wIejGUNEPGsXs5PpG19a1SDVbj9PQQCIa5JSMVtM0UaxXJY/wON+L8rr+8ZuouJ/6MXW2Qig6ObRYsGfa+Rr4JrbQ==
X-Received: by 2002:a05:6102:2a53:b0:470:501a:b992 with SMTP id
 gt19-20020a0561022a5300b00470501ab992mr3659537vsb.19.1708941785489; Mon, 26
 Feb 2024 02:03:05 -0800 (PST)
MIME-Version: 1.0
References: <20240118110216.2539519-1-elver@google.com> <20240118110216.2539519-2-elver@google.com>
 <a1f0ebe6-5199-4c6c-97cb-938327856efe@I-love.SAKURA.ne.jp>
 <CANpmjNMY8_Qbh+QS3jR8JBG6QM6mc2rhNUhBtt2ssHNBLT1ttg@mail.gmail.com>
 <ZdxYXQdZDuuhcqiv@elver.google.com> <17ec4ca0-db5c-47b7-ba8a-ec1d0798c977@I-love.SAKURA.ne.jp>
In-Reply-To: <17ec4ca0-db5c-47b7-ba8a-ec1d0798c977@I-love.SAKURA.ne.jp>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 26 Feb 2024 11:02:27 +0100
Message-ID: <CANpmjNNH1iQmD5F36+3Vj4vKy1oZkFuUcCq51wuc0qSRcJN=0g@mail.gmail.com>
Subject: Re: [PATCH 2/2] stackdepot: make fast paths lock-less again
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Andrey Konovalov <andreyknvl@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, linux-mm@kvack.org, 
	kasan-dev@googlegroups.com, Andi Kleen <ak@linux.intel.com>, 
	Andrew Morton <akpm@linux-foundation.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=rOxakaS3;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::e36 as
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

On Mon, 26 Feb 2024 at 10:50, Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2024/02/26 18:22, Marco Elver wrote:
> > If we want this fixed in mainline, I propose that [1] + [2] are sent for
> > 6.8-rc inclusion.
>
> Doing
>
> -               alloc_flags |= __GFP_NOWARN;
> +               alloc_flags |= __GFP_NOWARN | __GFP_ZERO;
>
> in stack_depot_save_flags() solves the problem. Maybe this is easier for 6.8 cycle?

But it's unnecessary and may hide future bugs once the series in -next
lands. If we remember to revert this hack then I don't mind either
way.

I think Alex proposed something similar before we had [1] and [2], but
we decided against it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNH1iQmD5F36%2B3Vj4vKy1oZkFuUcCq51wuc0qSRcJN%3D0g%40mail.gmail.com.
