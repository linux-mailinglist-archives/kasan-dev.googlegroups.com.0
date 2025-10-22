Return-Path: <kasan-dev+bncBCCMH5WKTMGRBYOO4LDQMGQE7DG65KQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 09DF1BFB340
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 11:44:24 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id d75a77b69052e-4e89ed6e110sf32253891cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Oct 2025 02:44:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1761126242; cv=pass;
        d=google.com; s=arc-20240605;
        b=Pg5eVFFd15M3KWF0RTwwol8ihvglsag4K+RVd0/+jHe4DyPlfB28nW4Nri3xvD2D2S
         hgt+8neNag5gu68amfD1QdUImOn2EK5ZTPax6QyuePJ0pjRpZYwAVLTy34IfJor1xa1U
         K7UHFT+3nWsz2yGkg9/OplhV2XFBtS5J85/0e2zFrIYhbERyqnNniwG877CHBEVl327q
         aXLnI9XQxFPXnGZhUG5hwJNwfqyo6x0EMyUt53BQBDZ/sy8fxsMO/fttXasX1uW7VLsz
         uw5zItS0mFi/6zk6Pv55JU9C0ue4wC66I3s1n7pGNeOrTuPyTPhDjI0uRf/Tma97gOV4
         rWJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=DbNwqiLzeqw9TgGcVfMA0iy0h/eBjRPYnQ4uz38mQ1k=;
        fh=QjkzJPBJzvxlb/MjjvrTOdhYfBGvN1M5sWL8onYVRSs=;
        b=SWiHqaosg3tMlJIqY+CVAem/RCprGWgrl/MpcbCXEB4FkpebCgkLV2Go/yEO14f1BK
         UfXtvuPBrJLgyLZIGxGH5rJZ7F6/lp1sRVk6SYpTCbwzGnZlE+Kw4kTjDwV8Uyp060kp
         0ETwM6+sXR3p1uwL3cDKerv+3Mg/4Lt/QTBI7TjMXvHNaBzlscD2zvMZSAwq37kiWN5d
         FBfd8mUrH/UpB38aVYCsgJ6ubjgBHWEsNyoSRZ3O2+V2MDbmqSEdt/1SBqy6BExr8NEN
         qWq8uMsBdQKJ6BQ7lXHjn0M/JwbElcvvy5Fhn3QM+7WtlxW2NAfogWeubr/g/+tnJGs7
         zJUw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="H9osT/6V";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1761126242; x=1761731042; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DbNwqiLzeqw9TgGcVfMA0iy0h/eBjRPYnQ4uz38mQ1k=;
        b=muCdYlct8OCGrWoO0LgY1E73Hn0YoMkXAyBMhGJcDOvwa8R3lnYvv9VF/9gus7/Hog
         rrkIWPJpj+6pW16yrR7+5Cz/ZcupVn26VyIQklJb1bYEhpyaNXeVfiQJxAvGJYtrfstu
         +um6yrIASeKM74RfhirI6mpYnZjiL+2RV6sadOL8hcUoyvSfIaXYcxbgXf5GWwpNipQY
         UEtZW46BWPwRvrfY8tfEvB3Ts/DAeqFM4ObzeasCt8sZrw7i8GZjtZdNo4daKDOOHcJd
         giYkCLb+LLU8W07HWYZoKjponqZrudAR7G25dPKd4CZNdJqMr3cU+6LW6ewxvQzZMlTF
         Vb6A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1761126242; x=1761731042;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=DbNwqiLzeqw9TgGcVfMA0iy0h/eBjRPYnQ4uz38mQ1k=;
        b=hWAXYfSM0MoU7r7eAcetekWpzu8hAIJCV8guo/GUIFon7pJlMJdaCZAfKTqxs5NQNs
         W3r7E+Rckgc+61NOUfOcJA8SOp7g6+6LoPSFAkwTGlYfBl4AD4NwidRN0YH+npLDyZiT
         P0vxlXWZuTXOsRZ93yuttKRRuSYmRzU2WK76oDFTiqkk9H48BXP7NdFi0TA5rld6ZDJH
         +TiYI71jhLDGTxhV0eYD69jf1VxulFLqqKvhbwE/TTioEEoKVfPpaKbutfUkZoOvzhmz
         CR4kCyBkf7sE6S4fxqCqbrE07lQ8H5WpshrHr7hVbdRFLJukDJCLo8297cgKriONb7VJ
         A+jw==
X-Forwarded-Encrypted: i=2; AJvYcCVpUtfYlV+DDzCgZqz6R7+Bt+DeRhebvbiTXoZIiWjbhZ+kH7ckBQfTxkImc9Ip7TFZEffVOQ==@lfdr.de
X-Gm-Message-State: AOJu0YyaktMYnB0AN0KxJSkViSHV4DzvQYpcuuM/pAhXLvhZTJN2/ZH3
	klCEtThO7C+dT44tbNkAkLZd2gwZIuZkHwUqoxpXdAojVY4NoL4W8UID
X-Google-Smtp-Source: AGHT+IF8K1j+kp1DFEymM7Ug6Dg7QgRualFLLJVdwkYk5pWzvvlKnY3ZAkjKF+WmnJpx3vbW4HELAA==
X-Received: by 2002:ac8:5792:0:b0:4e8:ac66:ee42 with SMTP id d75a77b69052e-4e8ac66f458mr201068041cf.27.1761126241883;
        Wed, 22 Oct 2025 02:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd7fxBQGbdI74Iy+e2GOlpeKev38KEsItga4/cUao5es0A=="
Received: by 2002:ac8:5785:0:b0:4e8:bc85:da00 with SMTP id d75a77b69052e-4e8bc953239ls61738761cf.1.-pod-prod-05-us;
 Wed, 22 Oct 2025 02:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVkmJttAhG7kkreFkFCgQTs4EE/sRt9zOZq2IkmXKNpLGUoGMbRCfzrzrgJgr8ZgmnvU6bC9SBRXsc=@googlegroups.com
X-Received: by 2002:a05:622a:1391:b0:4e8:a6f8:e3cb with SMTP id d75a77b69052e-4e8a6f90f50mr224803201cf.69.1761126241158;
        Wed, 22 Oct 2025 02:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1761126241; cv=none;
        d=google.com; s=arc-20240605;
        b=azDhJVqCWz7LdxBEQZbldYbCvTBMRSaj4dlI/6WBCWafw1H82XWwINgLwkoTfvnzl9
         d4s2e2+AVeCNZjOxdFRxlWNzlGP4biIsMzwiMfSMAwVteUYa44oJS+dXr0r4c7BdWQr/
         EKjU3mgKGEU/Oe7usQZKIAKBGVcaPLibXuqYGg3/0oqTeDpVFtkW5dRK9lBGBwHrBm+U
         kv0izdM038Cw040D7fLlMfGurGFA1LHpdAKqG7Txi1sm9NMsp+cMh+N+yV0tHSyXwUEz
         NfhZHqrGLf+LCl85UiQQva63fX7LTc1uagxNIH4FOhwFnS7ndCTGsEuSNS+l5yw53V35
         Igzw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=UIlHCnSUg7Sz6EMxU9JoMcjFVpE9+lYXJBhrkV15us0=;
        fh=vkhTpWkO+KNFIu+ofudA0MtHw93aOaq2qEesylV6i7o=;
        b=Zk8lHhv6LngR1SqPjDWGlnIe429wqOzU9bzWA9sC/Vh2iLoFYYSzQ6Jgd2aU9fu9XI
         myzQcwMdxl1rqpvY6D3VhaTOYO1Bx1zZeDqBCb87DQ9vYpUEHJLYorffSKGxazlGrlJf
         E9pAp77Z/bg6UlA6v2OvR545Zwy1UhbKY3M+I2gi5U/yuxVYBMoXjlVKA+JEymCnREwp
         IWJbJsQIJ3PFzMQD+vVd8ZAfPu6i/PEbbD/ucWeTnR8UEcAftvjs4A/nAGgGutHcHBZ9
         SjFqswFYIMvTGsHnmWi3QYmwsY1WhH7Fle+a00BQfbcYsjzl0CFVU6CsO376fEKhH1gr
         Blug==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b="H9osT/6V";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qk1-x72d.google.com (mail-qk1-x72d.google.com. [2607:f8b0:4864:20::72d])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-87cf548769bsi4286226d6.4.2025.10.22.02.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Oct 2025 02:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as permitted sender) client-ip=2607:f8b0:4864:20::72d;
Received: by mail-qk1-x72d.google.com with SMTP id af79cd13be357-89048f76ec2so884676985a.1
        for <kasan-dev@googlegroups.com>; Wed, 22 Oct 2025 02:44:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUrXnGAf7UF6G3SKg9SAIt4cjA5bkSMkJqFUZxoV5iLtNSndsMGE3Sn21IXZSB68A2Wph0Goy7SgcU=@googlegroups.com
X-Gm-Gg: ASbGncuzKH2W7PkjtLMzY+QtbUhQv7E6s2bfIeR0vgYYI5VtxquHrsdlsoy8SRjQVwu
	bqXaM+3O0VJifG5xl47AfbgdTSR+VHXUE6QsGY5zKvNVX2ef06mi8yK1/Zdu0s6jIrYxGNueNyI
	AnTi+CzujSPb/WcLHvV5lmtiSE1yBvs5jVN8z/wnmk9bXu92TaxbbrfnxwJHnf3fPAcLOIwZpWp
	2HJf1B9GTi0OkXbcjXZWtV0u71DLQpVXbfHJb8K/6jxdloPM61LOj0FlXPpNG+MMLbr0uOvrk2m
	VRF4DlPRYbeYhKaDB3Tr53gZYVbkDnZjCiys
X-Received: by 2002:a05:622a:1450:b0:4e8:ad2a:b0cf with SMTP id
 d75a77b69052e-4e8ad2adeb5mr171413751cf.9.1761126240464; Wed, 22 Oct 2025
 02:44:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
In-Reply-To: <20250930115600.709776-2-aleksei.nikiforov@linux.ibm.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 22 Oct 2025 11:43:24 +0200
X-Gm-Features: AS18NWCvJIsDRRmmPGlRlrKGRNevHIxIdBHxPohsj_ockyK-Yc0HtDMQf0r6L8g
Message-ID: <CAG_fn=XM_HRovM+VanVsNoi2ug1HQ1yx8oBhYAj0sVDJsh0nfQ@mail.gmail.com>
Subject: Re: [PATCH] mm/kmsan: Fix kmsan kmalloc hook when no stack depots are
 allocated yet
To: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>
Cc: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Ilya Leoshkevich <iii@linux.ibm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b="H9osT/6V";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::72d as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

On Tue, Sep 30, 2025 at 1:56=E2=80=AFPM Aleksei Nikiforov
<aleksei.nikiforov@linux.ibm.com> wrote:
>
> If no stack depot is allocated yet,
> due to masking out __GFP_RECLAIM flags
> kmsan called from kmalloc cannot allocate stack depot.
> kmsan fails to record origin and report issues.
>
> Reusing flags from kmalloc without modifying them should be safe for kmsa=
n.
> For example, such chain of calls is possible:
> test_uninit_kmalloc -> kmalloc -> __kmalloc_cache_noprof ->
> slab_alloc_node -> slab_post_alloc_hook ->
> kmsan_slab_alloc -> kmsan_internal_poison_memory.
>
> Only when it is called in a context without flags present
> should __GFP_RECLAIM flags be masked.
>
> With this change all kmsan tests start working reliably.

I think this makes sense. The whole __GFP_RECLAIM filtering was mostly
for poisoning local variables, so we don't need it for allocation
hooks.

It is still possible to pass __GFP_RECLAIM to kmsan_poison_memory(), but:
- it is actually not used in the entire codebase;
- the documentation clearly states that kmsan_poison_memory() will be
allocating memory, so one should be mindful of passing wrong GFP
flags.

> Signed-off-by: Aleksei Nikiforov <aleksei.nikiforov@linux.ibm.com>

Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DXM_HRovM%2BVanVsNoi2ug1HQ1yx8oBhYAj0sVDJsh0nfQ%40mail.gmail.com.
