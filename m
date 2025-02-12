Return-Path: <kasan-dev+bncBC7OBJGL2MHBBE7XWG6QMGQEAPCA5QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x1040.google.com (mail-pj1-x1040.google.com [IPv6:2607:f8b0:4864:20::1040])
	by mail.lfdr.de (Postfix) with ESMTPS id 46344A323C6
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 11:44:38 +0100 (CET)
Received: by mail-pj1-x1040.google.com with SMTP id 98e67ed59e1d1-2fa2e61c187sf1612993a91.0
        for <lists+kasan-dev@lfdr.de>; Wed, 12 Feb 2025 02:44:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1739357076; cv=pass;
        d=google.com; s=arc-20240605;
        b=An2pGCfQ8zD0xH5rTUp5Ndi0+8wYpoMTWBRt+LOvrmQZOOJMPObMg6wFFFjUrwp5jf
         mwgy5n/OYYbuEA6AzJV76wGiDxo+WON+W2R3zehasEJMT8ST/eWIY4QuQGN73glyY+9P
         TsSCDd5rSGtjSGmKTBupgPXU68VQNyuZswjCzLtcczY2Iy9uTuT9WBBgpfMmit1eOyAA
         sDED1w5qRXlxKdgxiDT72T7e5Q6NA5ppz+O6g5bYwc0nUm0QR5XAsYA/t7cAKYIDE8nE
         bg9yOjeRuZ7brRoIliXWSKMqBjql6t9OLqtxbkV3Qu8ZXjW8XSE6HDwmimcN6chv1yzz
         p7HA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:to:subject:message-id:date
         :from:mime-version:dkim-signature;
        bh=WjZtWaASH6/khkYSKyqRMgrk61llG7vPhwybV9yXhhE=;
        fh=qIyu/u4dK1u7/IMXTB9nPlmxgFFRFadFpxF5cKjQvnU=;
        b=XUKwz7d952Kn2jv/EDxvHAx+hXnCN4NOEKxhwIPQLnEIilAlEz/Bjr6Ss8LWqdmvt8
         a91u4lzyRrXeMJ1mL8qCKsxtWVRMAv0SwszoL46QC6+E5iUow1ghFFRudr411FLA7Dz2
         a/3J6N+5Zs/8AVsw6qsfHVxDTxI66hSQReQ+hESSACe/2qNKQPA1QNalIpEk8fpYGHzb
         1nSESO8sBmXz2x7e/gicCoCN6B+K9N0IMBkdejfYc49eKMUeXUvlIIbuHal78azGahbZ
         n8QNtUnOFb8W2wADLfVU8vExGrq6zly7tBSiHef5Jr8xjQOg020UQBG1kAJ6bbryrZM/
         wx/g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R6oCTWaV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1739357076; x=1739961876; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=WjZtWaASH6/khkYSKyqRMgrk61llG7vPhwybV9yXhhE=;
        b=FgyrXDMjek2W7q3P+Qb8icmdF9C2v1qcwz9mobNL0LgCDJzYPO4d6bFAZt//xJAras
         KuI33vRZOizCTjoJulGEr4KeKV6XUi0TV03iHVDImqby7c4BvOU/n+6PAVETlrRDWPGf
         /mxBpleLi5+/gHDG4Xb16kJt7FRFwfas/nTFi3/lB5YmUb9Y5lNMpffIs1YzRzyr9BkR
         oXnnqLAH0107MsMpjnT7FZTLSDao0e81c4yZ3lNq6Btaooyaev66AIwB4c1685ydn83Z
         7xb63YZsrlZjcBwQc7WSd4Nz4SYB3bmUqzAhXUeKQNIJHChUq+EjRxyou7ob/wyti/na
         66JQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1739357076; x=1739961876;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:to:subject
         :message-id:date:from:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WjZtWaASH6/khkYSKyqRMgrk61llG7vPhwybV9yXhhE=;
        b=eimoDzM24VkZ7zOk19AGEu7vaSiLkC0pYQ+3R2ugJWW+uhX0tCX6bjWK0XDNMgy0lD
         Ztep9OvrNnmXvSl4e19X4gqUUttmd3kaUAgTTO8cqDIu/oMuHs6VGLzaiSyQC23tryx1
         wiiBjHEGpBs3jH4ZXJG+ekoTEKVntp39fwlUsPydL4A8mQCbZGTAsMEl7bvLNLuFUaV/
         yEkP8jtDjPpw3K+PKt1DEjIb8FUwdk5oRTJVqyUvbaN/8kt/0O1KYhG8zcgn8dqbcz5N
         iULtQ9FoLAsv5ky7p5bDuSSsvm1OV7s8QPkLSKmzFGIj1pfdKrLvgE2nJG2VBfMfOxUG
         rUQw==
X-Forwarded-Encrypted: i=2; AJvYcCW4H17y5VmUZqz2+tyw/HFFFHC7Y2kveP3CnOQy79AV4m1lF4dOHSr+9h7Enf7qCtLtZ9Z2rA==@lfdr.de
X-Gm-Message-State: AOJu0Yzrorh/k0530sX1wnM5brTPpEw1IbgkiR1fdbr5J5Jaq5+NxCGj
	QoIKo7hBxQuZ4RpipGrRz7AMUnDrjrkJha3AKzXENO6R6DAj51t6
X-Google-Smtp-Source: AGHT+IGJxOc/Zbj1l0XD6mRra/8j9bjS8IshXlKfwwnA0yCQuothKubTeoXWuVJpAzU8hwXBM4Fscg==
X-Received: by 2002:a17:90b:54cb:b0:2fa:1e56:5d82 with SMTP id 98e67ed59e1d1-2fbf5c73c76mr4179646a91.17.1739357076148;
        Wed, 12 Feb 2025 02:44:36 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVHg7cKaleAp/z0r2bUoLOW9gVW12ftWEmX1IH08Hs8dKQ==
Received: by 2002:a17:90b:4ecb:b0:2fa:5364:c521 with SMTP id
 98e67ed59e1d1-2fbf5b38d6els712644a91.1.-pod-prod-00-us; Wed, 12 Feb 2025
 02:44:34 -0800 (PST)
X-Received: by 2002:a17:90b:1f81:b0:2fa:4926:d18d with SMTP id 98e67ed59e1d1-2faa0982d50mr11250649a91.13.1739357074588;
        Wed, 12 Feb 2025 02:44:34 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1739357074; cv=none;
        d=google.com; s=arc-20240605;
        b=LwF8UxuK0lN4KD9mQKLP6oL1f6uu9CKSbcsd8ouWyI3uuLN9WRT2T6R80qlDlpJy1v
         PTdLTcEh26j0tfyNrm8OqgEtLng5O5SYcl6duBfze4ZHjTR+mod+26GsBASeSfF3UzPF
         4apKiUrJ+rM93hKJEZDnzHxUfKFZ2+ipfzWQvgGqHOwUzbzfK/qooUVHm6PbjRxwn289
         Cz5OfABcPU/ZYoGkJXbuHrOM1ogTS4tBFB3PiMxZzMVpeDQwchV0OEt0XyQ9Aqzmn0Kx
         gNUfzKVjnt3qZUmJmpvSweA6V2x8Aqvusda9KIvZBIisBYio4UYYb5NM2pqI3txrBjmc
         rJsg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:subject:message-id:date:from:mime-version:dkim-signature;
        bh=8iRHAPhkgBH5IukW5HgI9xjFeCbMdW3nTpVIpAUPyZM=;
        fh=/+SeyH5QZNmSUuKMr3Pjlyqk5Rr3DnbYHTrkmelqHNs=;
        b=UsUpIVjxwz/jDnMgIaC4G7hvq1XshNObajvU5XeWrfA2tBXdrq80pD6Q/6Yl6Uw8FL
         AmlUGPIFTnP4961UWqAKgE+btH2pLX5fZ3n297JrNjWqt9IA3lVGwROW1CGq2BujGtlP
         aDV6NtGl7TD2OGPEqsFYKtvnTG9EymnNVoFIG4D74bMle5fqZozTvgXAuSlE4jg8dDjr
         43Foq3g5tl1udsFs5As4Wzl4sqWCqTmavTm176VCKPXXaobk1l4BO2YxRY1fTls9D9mq
         zHnGw2/P8ahUdOuicsiW/Z0AhX0W49z7jNseKby32qjuVK28SWivQGpcaCSIQLmg+T2F
         cZxA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=R6oCTWaV;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pj1-x1036.google.com (mail-pj1-x1036.google.com. [2607:f8b0:4864:20::1036])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-2fbf9738caasi51301a91.0.2025.02.12.02.44.34
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 Feb 2025 02:44:34 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as permitted sender) client-ip=2607:f8b0:4864:20::1036;
Received: by mail-pj1-x1036.google.com with SMTP id 98e67ed59e1d1-2f83a8afcbbso1091845a91.1
        for <kasan-dev@googlegroups.com>; Wed, 12 Feb 2025 02:44:34 -0800 (PST)
X-Gm-Gg: ASbGncuqlI54zXa29MTQoP+CsSicgaVVVh5A1+J20GdmC2YtHNa9NN3d55ykA8OzBXn
	Ys+RZahtNIm0xie2pjToQVJf/exFqwhH82jgTZG1e13gkC5U6TjdRQceNKZn4yvuyQhnabI5O0z
	oMu3hwCs6dgvQjjeleMMcPc0JoNLTg
X-Received: by 2002:a17:90b:4a10:b0:2ee:5c9b:35c0 with SMTP id
 98e67ed59e1d1-2fbf5c2c065mr3984797a91.9.1739357073580; Wed, 12 Feb 2025
 02:44:33 -0800 (PST)
MIME-Version: 1.0
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 12 Feb 2025 11:43:57 +0100
X-Gm-Features: AWEUYZl4txGy2OYz-uGuv68k_k0P2kH7fJWv4KbzmhX_QouaCZX5HSEFJt4jj00
Message-ID: <CANpmjNOuK8XPDbZtsL5nGnXb1d1yfE3h1z7Q4tSMezSHi3QCbA@mail.gmail.com>
Subject: Does KASAN_OUTLINE do anything?
To: kasan-dev <kasan-dev@googlegroups.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=R6oCTWaV;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1036 as
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

Hi Andrey,

In a recent kernel:

% git grep KASAN_OUTLINE
Documentation/dev-tools/kasan.rst:For the software modes, also choose
between ``CONFIG_KASAN_OUTLINE`` and
...
lib/Kconfig.kasan:config KASAN_OUTLINE
lib/Kconfig.kasan:        each memory access. Faster than
KASAN_OUTLINE (gives ~x2 boost for
mm/kasan/kasan.h:#elif !defined(CONFIG_KASAN_GENERIC) ||
!defined(CONFIG_KASAN_OUTLINE)

Why do we have CONFIG_KASAN_OUTLINE?
Could we just do
s/defined(CONFIG_KASAN_OUTLINE)/!defined(CONFIG_KASAN_INLINE)/ ?

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOuK8XPDbZtsL5nGnXb1d1yfE3h1z7Q4tSMezSHi3QCbA%40mail.gmail.com.
