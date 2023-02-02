Return-Path: <kasan-dev+bncBCCMH5WKTMGRBLUV52PAMGQEBVE23JA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id BEC106879BA
	for <lists+kasan-dev@lfdr.de>; Thu,  2 Feb 2023 11:04:31 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id c11-20020a92b74b000000b00311075338efsf931158ilm.18
        for <lists+kasan-dev@lfdr.de>; Thu, 02 Feb 2023 02:04:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1675332270; cv=pass;
        d=google.com; s=arc-20160816;
        b=egYOQxFIjgsOj7xp1HPgpLlIcg3sr4aVjt/eUYqRS3gN47BU4OBdRJpeK8nKaqyLTO
         CGe0IKVogpg41NVt+A5nEPuxvOOQjiz1fNAGRtNDYQe98IrmrotSL85HgngW+abFXgDZ
         HPo8r4q+2px70ttEu92gdfIRnTimYbtOMF9+G2ZEXknDUmUZASuGhIxORrjrLlMqnQwi
         4vPXBY5aVXaCFGNMThFwJlwqJAU7uDIZ6vnEC1f5gnu2z7K2ueCALIyw6itAhTel4j2T
         KOQhumcZCeeaif1wd8baaYWWpCyfekn1ql7y5D04ur88HlJwWsfR/6s5zxIp3uS1KoKs
         YDPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=WEL/icXS9wei5C5wzfFyE7S4B+BA4jqE1U19wQMfF6U=;
        b=rNPKch50bL439ece9+ODZEP7imhPCIhZy4/SOvqGrCSjJrpADorCZ/Nk2k8CxXfdM2
         yD98/awxnh/bx2apKJoOSgB51NZ7Iq9yqU2IJva8LMt9Z5qlR5tc7WFHi3M/MVisgJPX
         wRSO5HMHSB6yLXIDW8J2s57MZImyP9gzxi21bjVLmLJ0RbFkxMWKP9fw0Ua9PG0taXCa
         U8ADvhPaXLAkzXGhG8rwxT/eR2YyU7GzVksROUjOvY0H7TflqvIsTBqtaWW7ZDjcdwK6
         oZ384YT4Z0VRPvB2OEVaPhlHFnPMkHbbOpjOVXWHZUyyt8mEowD0zbUeSHM0OwoP3nGk
         1Nzg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="T7P/mMpo";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=WEL/icXS9wei5C5wzfFyE7S4B+BA4jqE1U19wQMfF6U=;
        b=D4jT+/wIKMC1WFDaloiMN/SJ2fVEjWjYh7KKbaIABlH/sTiA9I5d1pkCbTg1bAVtmC
         cuCzb0jhSK0Cw3YM/bN5HHayQBStP7/HvUV2wMBZzPPBdkMmA+0qvKmFXBIR63z6DoSe
         N4ePF3x9osvNpwldnuaUyfoKSoqC7+qHqsWUgGJGpBuFavw1DgSbbv3UfTq0xRxeZm+d
         2xU2IGvwgh2o37paqgohgNq50vYRYIAUZ/lSpFLOR8HaQ5Lc/TiIVln7EWfFcQ9RGolh
         J0hRUZ/U4HQnnXI7NL9//64lOThzdQmu1dshA3L7/zfNLuay1iTvUTMOf4BdC10YA/YK
         hJpw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=WEL/icXS9wei5C5wzfFyE7S4B+BA4jqE1U19wQMfF6U=;
        b=xuMk8dtLATghOYBfboDqhpvm9493uERP2IxoxvRMQaIZwTluZHcj/rve4Q0zGyI4tp
         Fomn5NqjCpKUl5/yu7qPVVZOXCeSgoLCsAxjhs7pmlwLwO2do2FiMKJvs/8eatrdXjge
         RXqizNuWpueAz2gUJ5kOPFH7ptVec00HYtTFyGuDbqVba0RzasffEV9/IWTITJ2GCPSQ
         +Utz4hILL7SoguS+wP++CIM0CQR97w7L1jsaE5h0MSuxjTgX9OOsOukCqHQ/4+fXNfnG
         EFoMozLpC+uG2Aton4rV0pqtiyH5YHNV6uFHrz7h0ekexTQEXn9y/ZpSJ1EVrgd3tcWQ
         eT6Q==
X-Gm-Message-State: AO0yUKUOqmPXFjNuBiSQBZOt8Azwxd6aMvKgCyf64Ejhrz133mObXvva
	ELhfoh7/6ltB5ae2NI6BP3g=
X-Google-Smtp-Source: AK7set8BuPMkGBG89c7aWLNr6IqFhJrZ1i1N9ypkTRvyNdMWtLbJHCfl1WGhBb8H06VXCzjckBesaA==
X-Received: by 2002:a6b:6b18:0:b0:71f:c39a:fb75 with SMTP id g24-20020a6b6b18000000b0071fc39afb75mr1395163ioc.40.1675332270375;
        Thu, 02 Feb 2023 02:04:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:1481:b0:6bc:6044:840e with SMTP id
 a1-20020a056602148100b006bc6044840els62286iow.0.-pod-prod-gmail; Thu, 02 Feb
 2023 02:04:30 -0800 (PST)
X-Received: by 2002:a6b:8f57:0:b0:6df:820f:beae with SMTP id r84-20020a6b8f57000000b006df820fbeaemr3236241iod.18.1675332269921;
        Thu, 02 Feb 2023 02:04:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1675332269; cv=none;
        d=google.com; s=arc-20160816;
        b=KhfOMg8OIvrujE30fKvqp+/OCXA9izXdrQPtyfNmeQUZdInnKu9CEaeWuwlBBlDFSt
         SJjc6dfugqjizpf5Qj2HYDQp3dyz8e1asIvJwzMBarh2YkUkcVCTzjSfCyrSoSqzNtQw
         XhaNLfAU9mDWaMcS5DByFRKmx59hDE3wFH+vdCAPHrumzM2LhEChtf0XwpjzocV3829z
         cNozhOVAUkf24WEs/MIZr9io0TFejW37unQLhaJB9y5Xm1EVnWssMlQpRpNAZgJoxd8R
         fzUGV0lvow+ARHTa9OGNb3k29mfUsBf5zpVZQg2ZAKXgcdEIs2DYlQLxJaRxHxvMTI9y
         r1iQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RdKAPor/0ql5fVXwvTpe95WItYbjw1iOZwcgd3aSLm4=;
        b=KA+khQt1FRlQ7QTbfYZrjPC8WAjvUWUZtCW5wRd7rZWDkhGfdXrNoHNi0E1PtN3bVH
         dibQeV4Rm+y4V19dEnGm6CwBzsNGJvWn73PPvNcCp5rKmNYSXkXU6t5VV4bO2xl6csb9
         nqlxZQuMvpTYscFpdTx5hzi7dkBDUxzP736hLK0SqmoH5CJycgNgCnxNWYx4iw+52Jf5
         gBFHeF+x4fPsD4RzwPmv5YPyqRQj0lH4oXt4V0QVn4bJqyci3u9/hP2ko3GWwe95ZYxv
         EuAIMXd/cJeXEQOwOYKOeIWN2g24S7+gNrcpcqBlLcU7ULpnUMZU/VXxuO12Jl25opLa
         mTcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b="T7P/mMpo";
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-vs1-xe33.google.com (mail-vs1-xe33.google.com. [2607:f8b0:4864:20::e33])
        by gmr-mx.google.com with ESMTPS id i22-20020a056638381600b003a84517979dsi2122628jav.3.2023.02.02.02.04.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 02 Feb 2023 02:04:29 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e33 as permitted sender) client-ip=2607:f8b0:4864:20::e33;
Received: by mail-vs1-xe33.google.com with SMTP id s24so1232018vsi.12
        for <kasan-dev@googlegroups.com>; Thu, 02 Feb 2023 02:04:29 -0800 (PST)
X-Received: by 2002:a67:fa01:0:b0:3d0:a896:51da with SMTP id
 i1-20020a67fa01000000b003d0a89651damr950443vsq.44.1675332269289; Thu, 02 Feb
 2023 02:04:29 -0800 (PST)
MIME-Version: 1.0
References: <cover.1675111415.git.andreyknvl@google.com> <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
In-Reply-To: <fbe58d38b7d93a9ef8500a72c0c4f103222418e6.1675111415.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 2 Feb 2023 11:03:52 +0100
Message-ID: <CAG_fn=Uw6CA+N-dd6e_gp+AhogohBUU0XyNCTtjF6MZC_fgiCA@mail.gmail.com>
Subject: Re: [PATCH 15/18] lib/stacktrace, kasan, kmsan: rework extra_bits interface
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	Evgenii Stepanov <eugenis@google.com>, Andrew Morton <akpm@linux-foundation.org>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b="T7P/mMpo";       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::e33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

> This change also fixes a minor issue in the old code: __stack_depot_save
> does not return NULL if saving stack trace fails and extra_bits is used.

Good catch!


> + *
> + * Stack depot handles have a few unused bits, which can be used for storing
> + * user-specific information. These bits are transparent to the stack depot.
> + */
> +depot_stack_handle_t stack_depot_set_extra_bits(depot_stack_handle_t handle,
> +                                               unsigned int extra_bits)
> +{
> +       union handle_parts parts = { .handle = handle };
> +
> +       parts.extra = extra_bits;
> +       return parts.handle;
> +}
> +EXPORT_SYMBOL(stack_depot_set_extra_bits);

You'd need to check for handle==NULL here, otherwise we're in the same
situation when __stack_depot_save returns NULL and we are happily
applying extra bits on top of it.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUw6CA%2BN-dd6e_gp%2BAhogohBUU0XyNCTtjF6MZC_fgiCA%40mail.gmail.com.
