Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZNMSLFAMGQE4P5Y2NQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33d.google.com (mail-ot1-x33d.google.com [IPv6:2607:f8b0:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 46D3FCCE049
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 01:03:51 +0100 (CET)
Received: by mail-ot1-x33d.google.com with SMTP id 46e09a7af769-7caf66b2866sf2273563a34.3
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Dec 2025 16:03:51 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766102629; cv=pass;
        d=google.com; s=arc-20240605;
        b=XHabDqeeoSZlPx01Z/I26VIa9tZ8QlxAMMBRJaJT/tCdsT+3R51Bdy4vLFwHJL+dC4
         +L58aaf0lOKBPV5vFsk8dvfJ0l1sZzjJv5TWVQXVVJM4+L4LFcc7jioVm5q/o6XdQFMU
         bgJKAbr5n3oqEIUcJfAxvONkQ3oS6i9JQAqz+pPulzcN0n657TsETHC0mGncGVutW2RE
         VW+v8Izz1mZ+asEebYoggGD/mmjwc9IkdP88k4fAKD2P4xsKYMnxGamIeDaAmyUcnWQU
         UcGYqEAFvknMKdRBOKC1Z1aGazdULUctplNSAXfjxHW9lXmJv8MXT2+NX9x1QhASNtNk
         ZlFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=O733XKnbhbafXRN/NXEic7ssrzZTELG9NNSjrTd0a7A=;
        fh=kM/lGZfg83SrqBGaM7JAYlWpwS7CC3rsPPLorFxg3bI=;
        b=hjQ00Aq8bpb4q41HAAUCE5XT6dnWbrCeUNiYBm0/mWf9SGV71hIdmxBS++r+ow4sbF
         FMySCR2Ip1DIbVdp1GsEtQSDFOow3y/DGJbTQW4m1dGsi2lbmlEBaVU693/all5g2yUx
         EuQHTI5ZyCuF0KVz6gqV0fNVr1KuW2IwZRnxRmQ7e9yO5tSOJwNz6la3GSVwzp/apj0w
         k6J6iLq5P2yWS9TY0JhAOYUXA01K1Mbq4oQUtbUf7ONI/2x3Iep2iW42wSmyyWfnHZa+
         7CDv/W0kUgVXXdY8XdNslVYdtZIB0Ae1ssHb3A7eFOZl9vb4uRYqeK3TJxtDjNXMPNB9
         0bUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OayOFEGJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766102629; x=1766707429; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=O733XKnbhbafXRN/NXEic7ssrzZTELG9NNSjrTd0a7A=;
        b=xCUVb4ihJEv0d5gmiPefdLlxBl5AZNEIUpILpTDuBoL6NCXLvIaa0Hi7yLLK1MMqLL
         0I+EEg16W8DSdAEL4UqobSyJ1rRbXlmULId9NTP0lZKAzzLvvQlmvYndXHUARWezrAtk
         RJlpDqTybW1io8uzZXZS8d1ldhPV9o3oab38SBuy/kyncAY7Gzf00YNK3bPTipd6ISz2
         FOxzD8Wiv0U2yGX1W3MKb0PMD1kImjAT7dXOpJYWw/4os/z+K0NELTkJyxUpbTY3XYpQ
         IIcFYASB2u/C21FfpGJO8SwrClCn2buDlWALDtpWZss4tdV3OBl1z6b9vIv636dwYWAf
         LlCQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766102629; x=1766707429;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=O733XKnbhbafXRN/NXEic7ssrzZTELG9NNSjrTd0a7A=;
        b=MHrPeCHOL5cFpwmvmwzIudd5uOFqI53wfx+hDZy7eUV28DA0gVqakzb9zGDIbKY5+t
         EV3Dqqt8UJfswxa4Onea++cQiMQ9Uq8CXy1Az6/iO+mGepPtACPRZzS/sfCa1nB9J0tX
         g+129GPv7ZISX39x39pSeo9NyOFouzyn2yinvfxB8MgpaywcRQronoTnX0+e485BIrEp
         NMOQ0FgIthDKtoo7OtsCHk5SBP5e53zIivE1pNiuYdU0WbpdtdT2MDkWDX4liyyQTQic
         2yL3lQ9ePZ3rIQg/MS0ho3djsRbVUYm7IUW1rVwVJrFN4th02NUbzXsSu3UmytzeUtRf
         sA0g==
X-Forwarded-Encrypted: i=2; AJvYcCW++MahXedoTBl12rZ8hH9PJBgCycc9nns7mhk2ZsflQM2OUvrArfMVXtC9gTtXwqnJulE5hQ==@lfdr.de
X-Gm-Message-State: AOJu0YxrXsmQKKkT+hjpKXAVObvjAVEk8dOzZaTnruSoZ+r9hRvdH+MS
	HMYujM8vPQf7srGpQ0mrptvq5ZEBiXAQ3a6o2Ez9lt/vSMCHHE3Svakw
X-Google-Smtp-Source: AGHT+IH9e4RYaTLL9HvbFsQ9syeILLzKAE1oD8dDMHpP+wk3Bqzbphx71vfUGWiz2vvEmvTXbb+wcw==
X-Received: by 2002:a05:6820:827:b0:659:9a49:8f92 with SMTP id 006d021491bc7-65d0e9fe020mr636491eaf.11.1766102629425;
        Thu, 18 Dec 2025 16:03:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWajJg58xFYl0d9yotzApPd4Aob1fjXhNap1AoGPSydkuA=="
Received: by 2002:a05:6820:7404:b0:65c:f62a:5ab1 with SMTP id
 006d021491bc7-65cf62a60c1ls1124237eaf.1.-pod-prod-05-us; Thu, 18 Dec 2025
 16:03:48 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVWJtfJDwzIZ5fM+5RtcFbNz++u1+jzIHr8f7jJ9vWSuflPUluUTqKc3Tm11oC+7n3BWgaRSveV6SU=@googlegroups.com
X-Received: by 2002:a05:6830:4119:b0:7c6:a2da:ce4b with SMTP id 46e09a7af769-7cc668a4bb0mr684269a34.5.1766102628443;
        Thu, 18 Dec 2025 16:03:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766102628; cv=none;
        d=google.com; s=arc-20240605;
        b=d/zXa2DBdv5gUrIohU8xe+ikKq5JcheERK+Uu4rzwHWS/8jmK8tHRxfEjMSfoLki1J
         JUSe4kVPH0fwtcCoV+KlF7JDDe85Ak9VMfs/oDvpQiNE02JN7yeHPTX0OqyzfaJ+V/f8
         zS1k8jJCDk3fMq5mMqIGbV3xOyGBN3J2kUiOMOpnMi1s3LOpZ1zRhWOdx2uxkTZgYt14
         HJkKKdvtlxLqZYH5mOQg+AK0fVK878wDzre58K0pbSmLVGHUzKW21YhH+ul/Ea2IITPr
         HzRJJcQL2UXTZrAaQJG0Bppv8sT2EeS0KfZasmgmUKfTzzCE15lnh3+U7wzoM1zZbWvk
         LtfQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=J1OfIMpVDk62sfqPnD60EDcy2G+mtS7t2qT60UIugPU=;
        fh=Tm7TJzTbrfH74JOU8+/sgT63+6sV0ahgQxLktnFcktI=;
        b=Yyzq9iQijNpkOgnz8dST+HiZSQ2s3dogjptoG7xxLXQR5yvUCemDgIOYmV9lYtodVW
         8y5GlpSW/4Tbcro0uG0Wx1zaiohx+Ihg21PLybnoOjFNbcLA0sOA1kMzJQc2XjLamKfC
         lQ6i+LHoyH8CyQ+6fBJO0tym48Buf56/koX6C7c0bD+rcN0J0ebIJohoLJY+7AJ25Ryn
         udloYzTb/2b44ThNs8Plrpr9jfr094D42JELfbjQHhOe/Vz7mzVyp9L9xW1sYm0VvPrT
         Y+n/1QhJDcYL/bxSH6z85uKyrU/WUXmi6Lj3Y+JyCz4cQL0bll+6bRE74Jk+JYBA0ihB
         yxAQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=OayOFEGJ;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x62e.google.com (mail-pl1-x62e.google.com. [2607:f8b0:4864:20::62e])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-7cc667dedbesi55857a34.7.2025.12.18.16.03.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 18 Dec 2025 16:03:48 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as permitted sender) client-ip=2607:f8b0:4864:20::62e;
Received: by mail-pl1-x62e.google.com with SMTP id d9443c01a7336-2a0d67f1877so14757665ad.2
        for <kasan-dev@googlegroups.com>; Thu, 18 Dec 2025 16:03:48 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX4kYf+2Cjz2WyK0k8LzU+UfD2GCT1mhO8xAzarkQXImLjurIif3bbI2o47JhqvFMARUq2lQI/cZ34=@googlegroups.com
X-Gm-Gg: AY/fxX4whbMbYE+r8IKWdN5ENklNnATYz10TnwsiaBPptYfJNvNlAaXnFe/k85Kmks5
	fILfOty/DCaDE7Z1IHCOu5cQKP/NsKJeFFCzqfANwzBTnEi/lGpadqh4lt9lZsDpZgdgCIQ3qfw
	nLRnLn01hv1sii/yKymwnWSOFd5SlFlz6x58vwPM3BfVS52nexxiw4G8Gxbu4kZpYYj3wBisKhg
	VVBbZdINrPL5eIktQHdhGxalBfCuqZvE8F7vz1P9QtQvwdtz5E+Lw5TbViLrE1pnrBxwJpzVWB8
	TMK8RVH1Q1yXm98AHYgSF1YNZdY=
X-Received: by 2002:a05:7022:7e04:b0:11b:b882:3ed5 with SMTP id
 a92af1059eb24-121722eb273mr1139356c88.37.1766102627520; Thu, 18 Dec 2025
 16:03:47 -0800 (PST)
MIME-Version: 1.0
References: <20251218015849.1414609-1-yuanlinyu@honor.com> <20251218015849.1414609-4-yuanlinyu@honor.com>
 <20251218155821.92454cbb7117c27c1b914ce0@linux-foundation.org>
In-Reply-To: <20251218155821.92454cbb7117c27c1b914ce0@linux-foundation.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 19 Dec 2025 01:03:11 +0100
X-Gm-Features: AQt7F2qIdd3MXH1-hSjhv0OOTjwhSC0HJne1GRIX5sYTttEXnEWfzHwYmrFE2mE
Message-ID: <CANpmjNP1tMwdOUTNEqqTmWR2Ki8yDQ+H13iSHxzLkomj-WComQ@mail.gmail.com>
Subject: Re: [PATCH 3/3] kfence: allow change number of object by early parameter
To: Andrew Morton <akpm@linux-foundation.org>
Cc: yuan linyu <yuanlinyu@honor.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Huacai Chen <chenhuacai@kernel.org>, 
	WANG Xuerui <kernel@xen0n.name>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	loongarch@lists.linux.dev, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=OayOFEGJ;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::62e as
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

On Fri, 19 Dec 2025 at 00:58, Andrew Morton <akpm@linux-foundation.org> wrote:
>
> On Thu, 18 Dec 2025 09:58:49 +0800 yuan linyu <yuanlinyu@honor.com> wrote:
>
> > when want to change the kfence pool size, currently it is not easy and
> > need to compile kernel.
> >
> > Add an early boot parameter kfence.num_objects to allow change kfence
> > objects number and allow increate total pool to provide high failure
> > rate.
> >
> > ...
> >
> >  include/linux/kfence.h  |   5 +-
> >  mm/kfence/core.c        | 122 +++++++++++++++++++++++++++++-----------
> >  mm/kfence/kfence.h      |   4 +-
> >  mm/kfence/kfence_test.c |   2 +-
>
> Can you please add some documentation in Documentation/dev-tools/kfence.rst?
>
> Also, this should be described in
> Documentation/admin-guide/kernel-parameters.txt.  That file doesn't
> mention kfence at all, which might be an oversight.
>
> Meanwhile, I'll queue these patches in mm.git's mm-nonmm-unstable
> branch for some testing.  I'll await reviewer input before proceeding
> further.  Thanks.

Note, there was an v2 sent 5 hours after this v1, which I had
commented on here:
https://lore.kernel.org/all/aUPB18Xeh1BhF9GS@elver.google.com/

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNP1tMwdOUTNEqqTmWR2Ki8yDQ%2BH13iSHxzLkomj-WComQ%40mail.gmail.com.
