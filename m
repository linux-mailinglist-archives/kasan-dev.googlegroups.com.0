Return-Path: <kasan-dev+bncBDW2JDUY5AORBD735TCQMGQEO4JGZOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 6497CB463D9
	for <lists+kasan-dev@lfdr.de>; Fri,  5 Sep 2025 21:44:17 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-45b71eef08esf16604555e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 05 Sep 2025 12:44:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1757101457; cv=pass;
        d=google.com; s=arc-20240605;
        b=XtM0BaicxQZKqbaIrPoUxoAFHxXk6jYT8KpAIEJ4go+xM80nj+TSXAz7yEYkilgcg5
         CXMS0T7SUAhe5QvooJC0gH1jAyXkKCR9jospVba/stu5n951a8MhQ6fwv21MjMmaVt0p
         hH2u5fBMsmGUyLQtL1s/1Oip2tGMyK9+9AjEc4DVkEWmT9VV1c9ESFEUcw/QjjGA3DGF
         aly8N5gXWj8zpvZgZRB44thlhuyiHe0FbuwV9q/HM9+PV9WwXcZSv3MaL451paA1wNLG
         L7DfSlF5i7YJW4T0p6Tz5eaNQOZ5UWTcZ7Q4yslDvVH6CdNZ/q+oJpehvea38EAy26hN
         18sQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=2tqmcUb3WP3E7PcKRftSW0d1b7O9Pv8cpgDwmCR9TKQ=;
        fh=CEBtVmFdrSrWawZ9QIRg/BhvixKmRQ+FRq0JG2HNkDA=;
        b=lPDRaxLQauerZVTY9ClLo5mF1+vYkNVfJt9/+sAGfc+B9gl1BgycYeQlUC3Avdxvt8
         7CrnkfD5ewR8geVv+GShCMNINuQBOQTmxOoJdJv/0agN9Jhx9vodJZzh2NclDGgh34ST
         EDUR7uW8Ps/7FH4ZZaklZqQeRwe+zEX38hgCNZDetNGsfXfBoLVdydUiZ6+aJ1bUi34r
         45ZHYBmJEk3PdgkVBfGdG6xYLvGxW7pgdsAGc2/SkXkasvfdJ4QnVmfArmdBEfmOeQ26
         XtVzP1QLjoBrHxyibpeD4emTCHXp9tIXnguIHu2tqz0ur6iNoVxGbRfyvCvcb/kA/+W9
         Xuqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PWN8iGmt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1757101457; x=1757706257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=2tqmcUb3WP3E7PcKRftSW0d1b7O9Pv8cpgDwmCR9TKQ=;
        b=TCxVordz9fRbNXxks1Fc5MVqV6LEv3MWLOQMkJ2+aOo8xfqn58MD/XqIOKfFFflxAQ
         dVb0Qt7q2GEU1Ch3KfvEo2nfuDHTMhcLuWAj5e9thc4Tc5bQepHEVs775DCWHvPPpWHH
         ilum/cy483qYxJCLSHrepc2JqYFyhA1H53Kh5yIkmoUR1GOyiaQyb7x0sgY2l1Yf5AYS
         YtivLwOQZQjW58A99dfbfHQOBqqKVZ1nqUOgWA0R7oMGKTM6Ppo3AqYArxbKwgWU6YBI
         r1HZ3EINBZFiKSXIu1I6M+MfhKzRHR4+vyqds0vmor7K1N15G2wwgKq4zI/Vu5gXciCx
         qZ8Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1757101457; x=1757706257; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2tqmcUb3WP3E7PcKRftSW0d1b7O9Pv8cpgDwmCR9TKQ=;
        b=lctz9sMC5ru5PB2O0yB23tZsQinS94IYY768QD08xIvAM4eKVRPI6eaKvE2V/1PDy2
         B/juc0sNUuQF0qDLSl/8PFc5TT+kYQOotyxBxNaGmPB8UA+7FWZXMMWABMTu5wZXi33K
         siI27qypzfHEdPcYPw0PRpt0fxa/Z8ShRJtG75RxlmE2bhehi0X84BcYGjymfysO/Xqd
         MTMYsQCpF9MWcA4MhCsSex0JWWnj7Kk8k+PCvTtXU97nX96idapO3eQXRgsWRvX8nnE8
         2Nwk2dGUpnfuRXgnVWLnRytoTcxzS/TZNFKFF0hE1CBh41ZRFTJMrUMuQH6PWtq8ZURM
         tBCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1757101457; x=1757706257;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2tqmcUb3WP3E7PcKRftSW0d1b7O9Pv8cpgDwmCR9TKQ=;
        b=Chd6u68Kty5ERL3gbLcTfUR14K+z/ua1IUnISLGp3xp6xCA28bHqoPV6Bt7mm99dNm
         J/Ev1n3K+Sa/DqpmVMus/38CPzSz2BuKtfd13WrSzDfyrsGEzmh8qaWUoesPMRxgnMwR
         boh39p6OJkO1ThUT8SDlIGaHxD/ZrNyZzv289szooSqE9Dao2P6NrnsVXmojqLY0Cujv
         /PZXyGXPwH8tAI6CiPmJlOiiczC9kU3G7O1t/u9Jp+sUrBKs56rgSbYnATFDqtwbz6vB
         0guG1hWW03m0wIQCawhAtCBqoREOMVDmGLJrVUL/6dcFxC0VnU40cvMBbiTYanFd2uCh
         GwBA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUDXURYs7CG/ed4LjhUpClakAxa+o5kc3+37lbiK7tbyd4xVo8oGjN7d176iIIDgYFYVOj6hA==@lfdr.de
X-Gm-Message-State: AOJu0YwckrbSYrVOVf3FwLuWqEQ/q+OAN1ZjSXz8DGH6V9n2sXT2O8pR
	6qIZXwqZn7u4cK/umbUsLZDXCPx+TN3ofJkjUGO41vowIgYjUP0szyq6
X-Google-Smtp-Source: AGHT+IFkUpFirL72AGaHcC/vJAYt8jpT5Z5qpn5FQjCdbJ3P9YY5PO2jjrolr0O0j9ueed5nz4aQiw==
X-Received: by 2002:a05:600c:45cf:b0:45d:cfc7:a16a with SMTP id 5b1f17b1804b1-45ddde9222amr561665e9.9.1757101456526;
        Fri, 05 Sep 2025 12:44:16 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZdQeIv/MHBDbcWurzbFUAd9i2kjKYWUF5h0BOIkdHiXgQ==
Received: by 2002:a05:600c:a68f:b0:45b:6a62:c847 with SMTP id
 5b1f17b1804b1-45dd809e167ls3501785e9.0.-pod-prod-08-eu; Fri, 05 Sep 2025
 12:44:14 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUuKGQN3ZUY0jrZP1I/Tx7N7R2hcV+qlAEny1ivEaPz129fmzn3z4+TV2x16cxivJcDenfh0xmhxZ0=@googlegroups.com
X-Received: by 2002:a05:600c:4f8c:b0:45b:9a46:2655 with SMTP id 5b1f17b1804b1-45ddde9264dmr557045e9.13.1757101453936;
        Fri, 05 Sep 2025 12:44:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1757101453; cv=none;
        d=google.com; s=arc-20240605;
        b=jeQiHjwuPtH/71C3xaCLgR5f1x1FNRAt5WP05XtX81Rm3yb2IZoRYndoGcbLFHwWsz
         4bNBi54eGHjm/FvRtVi94EAk1elNBeo4d95ABPdTWmqahlVCJCM63ATgz8IlorM1xx13
         sVFUcxiKbBR8PkeEKqSFfMGdf/TUh02+UaxI5D89oPM/KSjyuqwzJ2NndWmkDOW3y26S
         4eWGQ+stB7qmNKpf1n8s+sjoBA/MKlPS09IoOfv8JHQgZfUWhrEZJC78VFLSB/Jbn45v
         iiFhlkuhRnv4F/Wf8YpA9UrqsrHmbUwyDHAAZKZGaf+CFpqh6upPfEICUR0sG7ZRcD+E
         UWzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=5kSIyEkKJPNtcS4C9SW12B6CjFCMmyXxFbHsBSrhHlc=;
        fh=y1YSYN3Jl41ja64gGQ/AGOCEdC/IXcNnP5ToH01HAjc=;
        b=iYJGh8+9VCsvKijA9DtEztd0P2aKNmz+ECnCFgX7wYHa8imIq6FFIs0ahgBFZAnJZL
         zZbL2+Pzhi3g1ZD1Fu7CQ3EZqGJ2ZFlxFo6rpGOjROl/9GWKzj0MbK49si58hxdy1F4o
         joVckWAZh6cypJ2q/lBafLjwmzzYIe8Lso8qsQYLAgWnVNCUhzwhtsUskOrun7tZVpM7
         DeWPcVjgkyDGRmuOg6CQtRyN6JEPoDQGHElQoxnzL5jpBLdB9MCOseNgXHd/BduO9Dv4
         T3ZntOe6RDBrWDVsEIZ7N5jYVvnRp1jbAOZluS8l/aVgJG1Tlo1CPlg29p35kle845TP
         Zeeg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=PWN8iGmt;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x431.google.com (mail-wr1-x431.google.com. [2a00:1450:4864:20::431])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45dcfc3f635si1799875e9.0.2025.09.05.12.44.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 05 Sep 2025 12:44:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431 as permitted sender) client-ip=2a00:1450:4864:20::431;
Received: by mail-wr1-x431.google.com with SMTP id ffacd0b85a97d-3c46686d1e6so1783581f8f.3
        for <kasan-dev@googlegroups.com>; Fri, 05 Sep 2025 12:44:13 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXyrSLditBmuUZ8G5LNAKIJ3dgqVsXBC+NWYSCaKKJ9dkMC8bLPJNAwF/zHcIfS/mJdDmlMaZJcgdA=@googlegroups.com
X-Gm-Gg: ASbGnctH/a+qoT0H73cSPD84xfp8OemSzxqZCqq8HBmGtEgWOTCvjd7WGHC70XE+ZFy
	fvbqrErR6iJqXLmrH2KHRcS7OQG0Wuy3ltgofTauj7eoS3pAg9anb4CixhF5QFp6HGVW1bUyT/R
	DpNPO1aYRs6dYKw+8vb5zI8ozz9dxADV5odIUdKruwu6QGbrXsyldGxOP8WP4/VX4irr0DiR4/j
	IhBmrFOCN6D3UClWw==
X-Received: by 2002:adf:b188:0:b0:3cd:44a8:ffcf with SMTP id
 ffacd0b85a97d-3d1dd81e4b7mr13383104f8f.12.1757101453197; Fri, 05 Sep 2025
 12:44:13 -0700 (PDT)
MIME-Version: 1.0
References: <20250820053459.164825-1-bhe@redhat.com> <CA+fCnZdfv+D7sfRtWgbbFAmWExggzC2by8sDaK7hXfTS7viY8w@mail.gmail.com>
 <aLlJtTeNMdtZAA9B@MiWiFi-R3L-srv> <CA+fCnZf2fGTQ6PpoKxDqkOtwcdwyPYx2cFwQw+3xAjOVxjoh6w@mail.gmail.com>
 <75a2eb31-3636-44d4-b2c9-3a24646499a4@gmail.com> <CA+fCnZdWxWD99t9yhmB90VPefi3Gohn8Peo6=cxrvw8Zdz+3qQ@mail.gmail.com>
 <c0bd173c-c84f-41d5-8532-2afb8eca9313@csgroup.eu>
In-Reply-To: <c0bd173c-c84f-41d5-8532-2afb8eca9313@csgroup.eu>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 5 Sep 2025 21:44:00 +0200
X-Gm-Features: Ac12FXw8jIlx5I_GnULq-nTw7_htdTiBmfe6-tGy9IZcoS0RzVO8mAQjd7gKDAU
Message-ID: <CA+fCnZd9unSjY-UnEwc4rGkSRgZX3nrs=WgBb2eDQNEpZX10cA@mail.gmail.com>
Subject: Re: [PATCH v3 00/12] mm/kasan: make kasan=on|off work for all three modes
To: Christophe Leroy <christophe.leroy@csgroup.eu>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Baoquan He <bhe@redhat.com>, snovitoll@gmail.com, 
	glider@google.com, dvyukov@google.com, elver@google.com, linux-mm@kvack.org, 
	vincenzo.frascino@arm.com, akpm@linux-foundation.org, 
	kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	kexec@lists.infradead.org, sj@kernel.org, lorenzo.stoakes@oracle.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=PWN8iGmt;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::431
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Fri, Sep 5, 2025 at 9:13=E2=80=AFPM Christophe Leroy
<christophe.leroy@csgroup.eu> wrote:
>
> > Hm, I thought it worked like that, but then what threw me off just now
> > was seeing that zero_pte_populate()->pte_wrprotect() (on arm64) resets
> > the PTE_WRITE bit and sets the PTE_RDONLY bit. So I thought the
> > kasan_early_shadow_page is marked as read-only and then the
> > instrumentation is disabled for all early code that might write into
> > the page before the proper shadow is set up. Or am I reading this
> > bit-setting code wrong?
>
> But that zero_pte_populate() is called by kasan_init() when everything
> is ready.
>
> kasan_init()->kasan_init_shadow()->kasan_populate_early_shadow()->zero_p4=
d_populate()->zero_pud_populate()->zero_pmd_populate()->zero_pte_populate()
>
> Here we are talking about the shadow set at startup kasan_early_init(),
> aren't we ?

Ah, you're right, thanks!

I was confused by the name of kasan_populate_early_shadow(). I think
we should rename it to kasan_populate_shadow_read_only() or something
like that and also update the comment. As this function is not
intended for populating early shadow (that is done via
kasan_early_init() in the arch code instead), we're populating normal
shadow for pages that can be accessed but whose shadow won't be
written to. Perhaps it makes sense to come up with a better name for
the kasan_early_shadow_page variable too to point out its dual
purpose.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZd9unSjY-UnEwc4rGkSRgZX3nrs%3DWgBb2eDQNEpZX10cA%40mail.gmail.com.
