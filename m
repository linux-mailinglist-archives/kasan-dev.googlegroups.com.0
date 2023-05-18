Return-Path: <kasan-dev+bncBD52JJ7JXILRBQMKTKRQMGQETFR6VHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13b.google.com (mail-il1-x13b.google.com [IPv6:2607:f8b0:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id EC1F3708903
	for <lists+kasan-dev@lfdr.de>; Thu, 18 May 2023 22:06:26 +0200 (CEST)
Received: by mail-il1-x13b.google.com with SMTP id e9e14a558f8ab-33868d4a686sf9590025ab.1
        for <lists+kasan-dev@lfdr.de>; Thu, 18 May 2023 13:06:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1684440385; cv=pass;
        d=google.com; s=arc-20160816;
        b=QuQ+1V61Tu64ecder9sEGVv5ax7tVfnEyhG09zsG5RJk/1DWAASM6kVZnAvct8V8tV
         Oz1ORdVEHV2dnMOQqqIqWJKy5SS0BVyxRmqxZparvY/CtVtraarRfudNn87Lk2NAVRUj
         Mk6oxtRWDsmE4bpxeqoHnVf33xjvGgKfMJK9TooAhR4pWT7Ke+HWpPvv/jVh7/h89ZgV
         AWUInneINoPWZ7n2ItcfdoDMw4n3FNTz3U+LgZON9vBVpRbGbPcuI4a/O5zeUDIS5El0
         hF0+8RJZpcysJY85oWViV/1PFmzNhyLmkyF21Y0F3UIgZEKZV5t7fcwolUGaX2cn+Cao
         2PPg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=4na64q5Hr9dLBgUTv5Y5YoAUAvoVVj3RKqgpkMALWMg=;
        b=xDJbffc+XpI68V+4U4FlbrKziM8IqYt8hKxZhCzM+ZZ4CWDBf+j5C2r6c0YcEQZqf/
         xmB3oGTsd82L+mdlfZccxVQdsFkfYhAv6qk1q2YZ5hD6M4vlCqVcMC7Xxm/UHHm5CeJ6
         HghMQVOlko6SMl2VU/shjysvcWPFfDF1RgYK2rDss1JqqhcuOfYVD+ElQcY/L06FnJxC
         nmCigD2DQccKU8/KM37srvcoAjj91MBxqu1YoL09QCVuKmrd6qFKJrQCACy7xzcIrK4v
         U13F6D1XqyvLpWJUM5lsLN4RPhh8e2QSbxTrQhPpDXJKfY2UKIwEYm0+5K87xbSx5oh2
         KOhQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QwXTDrd3;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1684440385; x=1687032385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=4na64q5Hr9dLBgUTv5Y5YoAUAvoVVj3RKqgpkMALWMg=;
        b=cxHDAhI1kqE/DBCyJ2lwGQQaYvUbaXG2BpPjBZFZYy7HMRoMnsmHALKkdMl+F77hX5
         F2ohVN/bx7hNrAfxpVvIId9329Kpud0FpUrtzxzYjCjlA4GbZb7vhXwjYA4+cmcj4fF0
         R9fkhLXRai/uhe9nLt5dddz0fyJ6EKn3AJ0ZFFH7OPjOLpDiwKaQnwmRC3hp5Ugl+niD
         iq6PrYioAmdOgeSN4KqV1/uyfKb+qjpF6vG3ozISNwrXnVcaNu9e+Hepuu8QHIPx6McF
         vblRMFpj6/AvYy0kh6D8DPo4qyBboCvPb/8GrVCOdABpQ0pv/vSiDYCyPRDDJTfQ4czJ
         qRKQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1684440385; x=1687032385;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=4na64q5Hr9dLBgUTv5Y5YoAUAvoVVj3RKqgpkMALWMg=;
        b=N4gkc876qr8GDR8iSY+bOfrV2zwhQvfMCHwR81UGB16ozJl06vrtcKxgYU0jK/aoqo
         lLnWJt+LyuFqMDrt4GmS3ZZaiWQBMdDKeLsImqJR6DLU300FKvjY9QnMXJdjSAF5wB2F
         M5F0Eupcq+Yi5lt8MxnGx3iSXCvh0gTgUcXCcvcs2XdWD5qZIU/RVchjWVIi8n799E0c
         LootHKoFGFVqY6LAvZRlyA+LELyR9WuMD6I0E1WJpr1bGbbzIEMDHcHV9iSASCEmCPdK
         3/5UyIe8akFKD98dqIJlp8VvnZgmxG5IZKgWFqj2cch1zdNnfgTqIaV+3wKz82OpFLzm
         kN0g==
X-Gm-Message-State: AC+VfDxxluyxt5KgCsxRp7oWsqD02muzq8eEDYBDc8LM5p1QvySopLmK
	GaVN17tPShY00ZSzeTEWRvA=
X-Google-Smtp-Source: ACHHUZ4fCu1OOu5mQyqSrQwyyz8ic9gV0pEqeEytsuC2gIlO4JXPJ6GPROL/I5qZU2s1Er5x+RrNKQ==
X-Received: by 2002:a02:63ce:0:b0:40f:80e3:6585 with SMTP id j197-20020a0263ce000000b0040f80e36585mr1826221jac.1.1684440385346;
        Thu, 18 May 2023 13:06:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:f08:b0:32e:2d9d:f290 with SMTP id
 x8-20020a056e020f0800b0032e2d9df290ls304753ilj.1.-pod-prod-07-us; Thu, 18 May
 2023 13:06:24 -0700 (PDT)
X-Received: by 2002:a92:d1c5:0:b0:331:5340:6525 with SMTP id u5-20020a92d1c5000000b0033153406525mr5257099ilg.3.1684440384722;
        Thu, 18 May 2023 13:06:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1684440384; cv=none;
        d=google.com; s=arc-20160816;
        b=YLzgSox/KC22VlGNrH2bnMJ33TKXh4Gj40eu/PYq7+ApG9aVEuAZlblhi9fZ4QYiP6
         d9IRi838AYbonfUaolK/HwNWRxeCoj5OBUReKXTsXiJbYDiJs8EOblxuoniI98PA5bon
         B0v076ZmqnZhJ1QMKfO4f/JcZ4iunJkS/ENhi1kAsfh0vgZg48ffrNTUnJ/dhxB2sUU0
         gHYq9gOpCanhUUKTIO3faOpgwP/DOTakAGtGOkovss7uoPSubXKaUP0csBK2RkgKkzXJ
         hGfYD8EKFS0KxbbdXR9dM1fIoZnfcaLSUgCs0Jcx6/dLjJpmZlVN0zmRJzcZo1n7LCvN
         ziIg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=Llsf50DWFe4C4yt4CKwUU/mwMek/qP2tT3Isdnsoo/E=;
        b=Hzfg4QI4zvW6pBo3S6OpqL/SBpJochhoU1UiBImFWJd5bjzQk+UbzTEA71MhKMJ/kd
         5lb1zBDMPzLB8+dhzR6btLssUxnT57ncoAxDjEa4MnxcrDQ3k+xeFWuBvjCghMKSYl7t
         82trbv5498qzurSVG4n5v9t3CC5eedd2jgCARWK5QwYwDZEhwqgGHY1pGgkY101jIfUe
         4rmoYeOkL6MPrKlvy6f5Zqv/SbIfl4/JUe4fFW3uz9SABn+ohuSSy8fNdr+kc6jLuCsZ
         XEoEImGKooWG9kAXWs70DofECtCKcxGhQiWa+1F239W3cwbXSRnr0twizLp5hZpspPsq
         8VQA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=QwXTDrd3;
       spf=pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) smtp.mailfrom=pcc@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-il1-x12c.google.com (mail-il1-x12c.google.com. [2607:f8b0:4864:20::12c])
        by gmr-mx.google.com with ESMTPS id r14-20020a02aa0e000000b0040fa7700d64si203238jam.4.2023.05.18.13.06.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 May 2023 13:06:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as permitted sender) client-ip=2607:f8b0:4864:20::12c;
Received: by mail-il1-x12c.google.com with SMTP id e9e14a558f8ab-338458a9304so5305ab.1
        for <kasan-dev@googlegroups.com>; Thu, 18 May 2023 13:06:24 -0700 (PDT)
X-Received: by 2002:a05:6e02:12cc:b0:335:f8e9:2791 with SMTP id
 i12-20020a056e0212cc00b00335f8e92791mr26729ilm.18.1684440384333; Thu, 18 May
 2023 13:06:24 -0700 (PDT)
MIME-Version: 1.0
References: <20230512235755.1589034-1-pcc@google.com> <20230512235755.1589034-2-pcc@google.com>
 <7471013e-4afb-e445-5985-2441155fc82c@redhat.com> <ZGJtJobLrBg3PtHm@arm.com>
 <ZGLC0T32sgVkG5kX@google.com> <851940cd-64f1-9e59-3de9-b50701a99281@redhat.com>
 <CAMn1gO79e+v3ceNY0YfwrYTvU1monKWmTedXsYjtucmM7s=MVA@mail.gmail.com> <c9f1fc7c-62a2-4768-7992-52e34ec36d0f@redhat.com>
In-Reply-To: <c9f1fc7c-62a2-4768-7992-52e34ec36d0f@redhat.com>
From: "'Peter Collingbourne' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 18 May 2023 13:06:13 -0700
Message-ID: <CAMn1gO7t0S7CmeU=59Lq10N0WvrKebM=W91W7sa+SQoG13Uppw@mail.gmail.com>
Subject: Re: [PATCH 1/3] mm: Move arch_do_swap_page() call to before swap_free()
To: David Hildenbrand <david@redhat.com>
Cc: Catalin Marinas <catalin.marinas@arm.com>, 
	=?UTF-8?B?UXVuLXdlaSBMaW4gKOael+e+pOW0tCk=?= <Qun-wei.Lin@mediatek.com>, 
	linux-arm-kernel@lists.infradead.org, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, "surenb@google.com" <surenb@google.com>, 
	=?UTF-8?B?Q2hpbndlbiBDaGFuZyAo5by16Yym5paHKQ==?= <chinwen.chang@mediatek.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	=?UTF-8?B?S3Vhbi1ZaW5nIExlZSAo5p2O5Yag56mOKQ==?= <Kuan-Ying.Lee@mediatek.com>, 
	=?UTF-8?B?Q2FzcGVyIExpICjmnY7kuK3mpq4p?= <casper.li@mediatek.com>, 
	"gregkh@linuxfoundation.org" <gregkh@linuxfoundation.org>, vincenzo.frascino@arm.com, 
	Alexandru Elisei <alexandru.elisei@arm.com>, will@kernel.org, eugenis@google.com, 
	Steven Price <steven.price@arm.com>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: pcc@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=QwXTDrd3;       spf=pass
 (google.com: domain of pcc@google.com designates 2607:f8b0:4864:20::12c as
 permitted sender) smtp.mailfrom=pcc@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Peter Collingbourne <pcc@google.com>
Reply-To: Peter Collingbourne <pcc@google.com>
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

On Wed, May 17, 2023 at 1:30=E2=80=AFAM David Hildenbrand <david@redhat.com=
> wrote:
>
> >> Would the idea be to fail swap_readpage() on the one that comes last,
> >> simply retrying to lookup the page?
> >
> > The idea would be that T2's arch_swap_readpage() could potentially not
> > find tags if it ran after swap_free(), so T2 would produce a page
> > without restored tags. But that wouldn't matter, because T1 reaching
> > swap_free() means that T2 will follow the goto at [1] after waiting
> > for T1 to unlock at [2], and T2's page will be discarded.
>
> Ah, right.
>
> >
> >> This might be a naive question, but how does MTE play along with share=
d
> >> anonymous pages?
> >
> > It should work fine. shmem_writepage() calls swap_writepage() which
> > calls arch_prepare_to_swap() to write the tags. And
> > shmem_swapin_folio() has a call to arch_swap_restore() to restore
> > them.
>
> Sorry, I meant actual anonymous memory pages, not shmem. Like, anonymous
> pages that are COW-shared due to fork() or KSM.
>
> How does MTE, in general, interact with that? Assume one process ends up
> modifying the tags ... and the page is COW-shared with a different
> process that should not observe these tag modifications.

Tag modifications cause write faults if the page is read-only, so for
COW shared pages we would end up copying the page in the usual way,
which on arm64 would copy the tags as well via the copy_highpage hook
(see arch/arm64/mm/copypage.c).

Peter

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAMn1gO7t0S7CmeU%3D59Lq10N0WvrKebM%3DW91W7sa%2BSQoG13Uppw%40mail.=
gmail.com.
