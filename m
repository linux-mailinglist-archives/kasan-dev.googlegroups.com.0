Return-Path: <kasan-dev+bncBCCMH5WKTMGRBEVV5SGQMGQE5B3M2VA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 42071476F2B
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 11:53:08 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id a7-20020a056214062700b00410c76282c3sf6526234qvx.4
        for <lists+kasan-dev@lfdr.de>; Thu, 16 Dec 2021 02:53:08 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639651987; cv=pass;
        d=google.com; s=arc-20160816;
        b=sx6Qq3YzPnwlDCkPR5nMK5OP4zjpTwm6pheb7ipyN6U9Bra+NsVFRzQ93wYxjrVs7r
         oevQGPZeff2rkJ+nqKk2ChaOKfjq1+FMuVw9iYekbaAV8Qn7quPm3qNgS0SDnK+iAXxM
         B8BsYUZ0DCiKyuaOFxaPAz/wEJCK0Lt5TMBRkFGiuHnjnNeFH04NoBf0I+jsM5SRUgJR
         OSrkgLwf3k7iHZpc/DdJuJhi9OH/DV2/7wLEv0wk324ZxMo2CjP4E4YRxRr5wxcUP1lX
         fd/NUfBjN0qOe7Rjv++1wqzxRq9DJYYA3tp7J/bL1UlRQYQWOJXQOAalgssw3cHcyuuE
         Xpdg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=7rm48zo7KrUrCPqpNGTRmB7NMzG0q5NtQMEo1XR3Jd4=;
        b=fPKuw5YsZ74ShpcfcnYtEpdl2gv4hEL7OLJ+AiOnLndOcKQ1ZfMMH5cXYAVd9EAi5c
         gzSfN95PRX/CAEoCrmIjumg05S360QmSk7HxSN1RXCEMrKYverHzbjdrveAX6nLMj35U
         cDmcny4On7+9m6T+VRVQleZJAkKzv9t4JDgva1qQJxv71mjOBdZMKrSf+eknyZyHWXVk
         WksVwOPzymb6lJuVqVjMGP+8+6D6KeerKQVeUcy4ZDEW20ebPoGSA4YeB8R7hfnOmPBm
         mQq767vCo0REyGzJ9JJZYNOBOJVY0xAOB3G2XlSyBCdbSAiU/O2yBxVs+3OgY1DpEkbB
         fGrQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YwL+7Ov0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7rm48zo7KrUrCPqpNGTRmB7NMzG0q5NtQMEo1XR3Jd4=;
        b=eycsoaooUonUw7SaiKa7VnCsazs5D2ajtpxxDfnB//FjhncWj5PopqyXCoK8GFXTdX
         lWtEkivO1/shpbWyoIIyMNLeGZVVMWllcAYIA2H4bKPfel2K1tNhPKLoTiob8zSp4och
         i12ziZWhD3YKEBicP34mEpfk5f8eZjsK4vppWGVuNzs0A74/Sq6yOuG95R0dwsUqbOWf
         wqhDDTp2M84mmq2La/Qgew2lSDDxblEiScv3FXdmvjm84DkxT12Axes2c+9++0MIz3Wr
         cwRkTkbfxGMUWxuoe4q373O2wudlL8e5BUpdYVNoz7/f6mRDO+MuYK1xTKfLsLgnCEMI
         SncQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=7rm48zo7KrUrCPqpNGTRmB7NMzG0q5NtQMEo1XR3Jd4=;
        b=xbvobZue/j5SGpmY2wzMhe7xz5A1BStI3dEHPSY4fUF4oR5SdXHqNASD2Mg5YZvZTa
         f9ddI6BB95JspWUhdDNWxvhMEK7wbqX5upK8/7TXvWqbxSJJ1HwhCwcGt8cFO1h0wJyf
         GWp7+By/F+I9qXP1VBALsQhzy4npwA7AqJ0YMNhArtTZNl+HlISLZo3GquZaHfx6vKoM
         5HArdXKDOy7LFlPGppUjcLwfHOvtqFUVGAb8iE+jGpdcIoQ7INkk4ZNG2tdutW6bKs6Z
         p73173VQaP0wmKgP8DQZEhjBkM2s1n+c1LfV3O40rxh7IWn6Iqp5lqAYPjqI5Pplz11+
         T8aw==
X-Gm-Message-State: AOAM532mds5ESzzvT+lZZGdPHoxi7Bp5Dv0fTyATVvSgo1dAwP98m9Nx
	B+6NtDjJN1qx2qC7V3UMMS0=
X-Google-Smtp-Source: ABdhPJwuk8jRiwUDcgAyKBhJXZT1ytznJmX5ob7iOWFGM3PkWIxsY4nfMmV2cyet6Cjwi83KeRne5w==
X-Received: by 2002:a05:620a:371c:: with SMTP id de28mr11577242qkb.535.1639651987111;
        Thu, 16 Dec 2021 02:53:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:e40e:: with SMTP id o14ls2391601qvl.10.gmail; Thu, 16
 Dec 2021 02:53:06 -0800 (PST)
X-Received: by 2002:a05:6214:c4b:: with SMTP id r11mr11585182qvj.3.1639651986650;
        Thu, 16 Dec 2021 02:53:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639651986; cv=none;
        d=google.com; s=arc-20160816;
        b=YXOFIOxLXAx+/z3qM5wPtDbWwulQBX8IoqTSAJ3dKyvWPWN9aAAoS3hH1a3llxfJeK
         CRY/2tYwwAriJQv9D29GNtXBYBeE4fiDZIyzKRKtWvw0v5CK5SLwuttwf1H3wjXPn5+l
         qQFMlaK+v2BAF9ReWBAlSoOuz9dA42HijBQd1VpnfGhytgTnVbJ2bk5iaYSapHh7+1xr
         zDn6he4xZAKVF+mGzEuqTYsaVf/OveSXmYhxgynYMV5K43auMILLojroieJHS1mPQvjk
         tNGOgXf0zxRLK2xopo/BuYkHVumH3LWJn/JP7EHctHtm98GX2QnAeJqtAPOTqz/4oCC8
         0TiA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=6Z1eZM6laZOzleTxsTd2Yd1uJMPVObidWq6Pg28q0B8=;
        b=ax+4wVryWHCpJ2Ypi9HuLDlHZhYcyIrjRgPVE/YsW9hmNlRcvgvkWAD9kbTWEQcTNF
         qiRjMyyAjtCh+Le//Zg2CcgNIi8mhSiQYMzbq2aqVZ7wvFDR18gO/6vYM8c+p2PtgCU1
         Q1lKuWsSgJ1ogBLNGuy5VaK+yrfAh+LiT1E1rU3Cia3kwHGrluV5AdCpYO/VP++oRu64
         61EUA2NUaUYbzmdz1gc0MpdeFPEcc5rp+/Ualh5dIHHykbk2m5fHNwQ987jwVI9msuko
         X7k3KOPGuNLhGxKAhKxapMk2RdYVLnhv2bPCkTIeUu341UGbVbOK3ouESEfoxj9PGSA2
         DfCA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20210112 header.b=YwL+7Ov0;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x733.google.com (mail-qk1-x733.google.com. [2607:f8b0:4864:20::733])
        by gmr-mx.google.com with ESMTPS id i18si476749qtx.0.2021.12.16.02.53.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 16 Dec 2021 02:53:06 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as permitted sender) client-ip=2607:f8b0:4864:20::733;
Received: by mail-qk1-x733.google.com with SMTP id l25so13595902qkl.5
        for <kasan-dev@googlegroups.com>; Thu, 16 Dec 2021 02:53:06 -0800 (PST)
X-Received: by 2002:a05:620a:e0c:: with SMTP id y12mr11446382qkm.109.1639651986199;
 Thu, 16 Dec 2021 02:53:06 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <e82b75533a93a5fc85e24b782c6177457af0755d.1639432170.git.andreyknvl@google.com>
In-Reply-To: <e82b75533a93a5fc85e24b782c6177457af0755d.1639432170.git.andreyknvl@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 16 Dec 2021 11:52:30 +0100
Message-ID: <CAG_fn=U8LjS4yH=mGgvJu+AUOV=DgHaPDbTBFtf1LjxexWB8hg@mail.gmail.com>
Subject: Re: [PATCH mm v3 15/38] kasan: clean up metadata byte definitions
To: andrey.konovalov@linux.dev
Cc: Marco Elver <elver@google.com>, Andrew Morton <akpm@linux-foundation.org>, 
	Andrey Konovalov <andreyknvl@gmail.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev@googlegroups.com, linux-mm@kvack.org, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, Catalin Marinas <catalin.marinas@arm.com>, 
	Will Deacon <will@kernel.org>, Mark Rutland <mark.rutland@arm.com>, 
	linux-arm-kernel@lists.infradead.org, Peter Collingbourne <pcc@google.com>, 
	Evgenii Stepanov <eugenis@google.com>, linux-kernel@vger.kernel.org, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20210112 header.b=YwL+7Ov0;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::733 as
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

On Mon, Dec 13, 2021 at 10:53 PM <andrey.konovalov@linux.dev> wrote:
>
> From: Andrey Konovalov <andreyknvl@google.com>
>
> Most of the metadata byte values are only used for Generic KASAN.
>
> Remove KASAN_KMALLOC_FREETRACK definition for !CONFIG_KASAN_GENERIC
> case, and put it along with other metadata values for the Generic
> mode under a corresponding ifdef.
>
> Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DU8LjS4yH%3DmGgvJu%2BAUOV%3DDgHaPDbTBFtf1LjxexWB8hg%40mail.gmail.com.
