Return-Path: <kasan-dev+bncBDRZHGH43YJRBHNH6SWQMGQEOZBHNWI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd38.google.com (mail-io1-xd38.google.com [IPv6:2607:f8b0:4864:20::d38])
	by mail.lfdr.de (Postfix) with ESMTPS id 121E684742D
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Feb 2024 17:09:03 +0100 (CET)
Received: by mail-io1-xd38.google.com with SMTP id ca18e2360f4ac-7bff2d672a5sf158478139f.0
        for <lists+kasan-dev@lfdr.de>; Fri, 02 Feb 2024 08:09:03 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1706890141; cv=pass;
        d=google.com; s=arc-20160816;
        b=dgPBeXh0xz8MoNbxyfZg6SF+EWhGXbjJ7l5uKDckdJTHeMx+6nJUQuxHYJM7UNBkDL
         3/8hLMMQUNtJcuL6hii7eFM1wuvpY+z4kQ7kVM4OeB6I6LMZo2h99jPyCTiY08bvSx6W
         vB2g1Y3tVImXH20x+5SN2QwsJUw5BDcwiyh1pfKtTXKrVujKVJM5JFjWBQTKf+1Ios96
         fSXgOpVeIcWhpjfkHApK60Qf9xZACLUZHm9xZKUgs5vXagMWn7plJAxH3avOuNWfQTN+
         NYG9iJK80kwRsKDPjXC/sTyRSnb02VdJ/o6Fp52XWy6cnuWcCSM3UT6cImOiapq5W8d3
         73IQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=+CEQUXQz604/DcPJ9TdsuWaqeRreCA/AfEDhskAhlm0=;
        fh=Wo3jfVAb8SSEoLjUV42ci7C4yVk3M+61pl7r73ez13Y=;
        b=0OfYkkzhmPecZwLYjDdVP5XEvEhi+WKxK9wnjKxTTfSxobwR9LaUZATgmrjqK0DGdU
         BUhL+q1VbtIXcTjv+1paSq1mbLkaBngWYi8E75iGZfgHqUhZq7qlFANUVGx14WTzOkqz
         hnYlKqpO60iyrWHU04sEa0wtuFDaseUR+Kz+64tOlP8F9Jix40fK8yoYS6vji1nj0waR
         MErFN/i0D93HmLRKnSHBRUiDDs0kgcla5h2l0G6B6+lJT9aAl3xWcQQnxG62nGPHU3/+
         aY+PNGoOyZtkft1tA+Z5gpxv80EMwTUW3SgDOmPfn1cyrwhNqrQK+ttVcrj2kp46HgfB
         G+TA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="O+Qpc/P6";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1706890141; x=1707494941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=+CEQUXQz604/DcPJ9TdsuWaqeRreCA/AfEDhskAhlm0=;
        b=nUKfEijrtt2MK8D/Iwi69cEc2m+Z7tukmMQn/X2CJlARh2VoByNhbFCdIu7vq+HBOi
         4bWstWkFHI5ciV8cZvNlIygYZxU4ISztEGRGVVQA0VvXGaGvDXQnyQnGL3bjE0EtJ7CC
         Bu/TSET77NLDq2Gobcl4dKEPIgn2XwZONLm47soHcedtQE67LDcncSIF5SGBl/3yE5eN
         tDWo55iRi5N0XEkwxvhsh+Uei0URlXcWTeh2Ih13DFTOyJ9DdlAKnpAQFcJZHZgvyOjE
         SmqRFNFAsLkz637vR59BQ9ZDlOgoKdJ4hYhseyQfQLcJ1py/VGKyXQOFjY1OBDcoNaMa
         +N0Q==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1706890141; x=1707494941; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+CEQUXQz604/DcPJ9TdsuWaqeRreCA/AfEDhskAhlm0=;
        b=Wk9fuAfGBYEyU3tyGgG6V9Trn44LoxGoVAVgsCY81Cv2Q2SVybNELjwoL6GM7rNR3c
         8K3/21RocbMmxYuuKZ947Brt3XgQUQ27r4HbdsCEnkqa69q8n3UZsvYcqKDIWZww2ksA
         ynON1neemabP7kRe4sIVCeQg/9JfYK2fgT8Vda53WIf+f8gGQpUGAmq71x9uc00wVtr2
         W4LOymQx2PDWjYWpyvGSncLmb89ReyVPY4FEbYbOzVN1e7NwYQqfXYs0iGwPIjT6o8uv
         Jy+wbfR/hN/+sgs1v5lhPOQ1iWXlykQd4RPzW8/VFc2+UN8Y6M9FK/vo4R52rDPO9g1D
         pKqg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1706890141; x=1707494941;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=+CEQUXQz604/DcPJ9TdsuWaqeRreCA/AfEDhskAhlm0=;
        b=XIh5NBExw0iLbOrNS44JzA2MRbzMF9YGxsYsgN7Vrf/5MJg/RLcRoMMIQJKHrhyMRK
         KqGyI/AYqCqjzyhezpwMo/srueQo5BhB+EriOVnkZbBO1CZrirYO3QYB67mKS1Tfe9z+
         7whpGTPVEEGTdChpqZUIrs7CgwEwO+4ZyKhn5QsGNkVsPa5H2D+SKuESGDhhA7MKNbrB
         w9/Uo3p8AW3r8ZIzGquESyQvKRxiLNr4M1YwdHpN2eP+GJX+7EuUh05EdIVmly6pAEpo
         9lC1nzpjkhkW4t3a02ADP5FbALXcnKqoUZJDHiHsYb3Yng9X56QHJo72ofZvdHYr3p9w
         Nslw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YxLVE+YikidIRMZcv9jLUi5eh7J78XQZOp9bW9UzXGM53y2p+UD
	Sgv+/8DEivQhwH6fpnqpPo/f2NrtRoA4VwKvlRd5l/1OTQ7jELfj
X-Google-Smtp-Source: AGHT+IFh/WpSnrw/exoNozpK89OjFtP5IpoY+XDF0UZzvjCmhv1fPMsrMVGUKFziJBGlzmvljB1YOA==
X-Received: by 2002:a05:6e02:1bc6:b0:363:a69a:daa2 with SMTP id x6-20020a056e021bc600b00363a69adaa2mr3165041ilv.28.1706890141262;
        Fri, 02 Feb 2024 08:09:01 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:2411:b0:363:93da:bf41 with SMTP id
 bs17-20020a056e02241100b0036393dabf41ls562033ilb.0.-pod-prod-06-us; Fri, 02
 Feb 2024 08:09:00 -0800 (PST)
X-Received: by 2002:a5e:c207:0:b0:7c1:a6a:1d09 with SMTP id v7-20020a5ec207000000b007c10a6a1d09mr965981iop.3.1706890139899;
        Fri, 02 Feb 2024 08:08:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1706890139; cv=none;
        d=google.com; s=arc-20160816;
        b=lvP02/VT7eg4a2tX7epIa2UnzUrEnuPCwTa0VcsElONLMAGMYO4oSjSVO7ynsjzGNe
         H9oZX4ci4IlAMCr2nSMHkVwvOoSsT7D8cvuyw8rBO3NYW8F8snSryqwMohHFWhv882HP
         06kfvP+r9Vu6GdZZchoVF8x7iVNihEBKEq5SwCsAK9o4eNsaaaeXdAxUtfwVQ8PWiJSw
         s06rFmZjFMc9174+2t843e10pbGP4OSUhUi/V75PddjEAJQvV3k9O35/XjEE/Hc5DFF4
         sZ1vebZepj9flVns2BRz6MhNsoMPOTy3EpmdDjqSkT3wx3puGhBIqwKTtCIz4jRdIElZ
         i6jw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ObobwIusGY63NE/2MOWR+NbMWvgKu/d9ZjBL9g2lKRM=;
        fh=Wo3jfVAb8SSEoLjUV42ci7C4yVk3M+61pl7r73ez13Y=;
        b=i5tNSB+2mMVTwZ3AMeqSRrj7JhTANCv70rjWlpZ9wUoOgPKahl8Cew7cRO9YnXMV6e
         Hfc6TNU5E/1qMxlC/D0z02HIFF3QojmSR1NUaw5mbMcPdyG74OeOPL6EqnG4I+lYmImf
         XMw4fpSJyQ+6dYCfFtQ8oXYIchJvacaSBLon3HQ4NfRZFuQrv9fkROO1UpW31uRrkdvu
         pkOKwUhxh4p87g4E5Itscr64rrf53hgyawjir0ARcJfbrUZJBIX8OGzNeFq2mNnsMl0N
         qZfXd71kxZ3iLmnHVtmWWDSqvdxXNlIIbNYnDg50LWkimD6zyziOX2WmWuF0pJHuETlU
         Ak4w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="O+Qpc/P6";
       spf=pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
X-Forwarded-Encrypted: i=0; AJvYcCWR6Gt/CGFj0+j1WvtfxZLk90+Rd6oa5Tz81wzEc3WrorWFR1HJyXQf196GLYhSyFlFzMyZx9naPlVQ2GKe0l0lX8abZE0Z1vXqBA==
Received: from mail-yw1-x112b.google.com (mail-yw1-x112b.google.com. [2607:f8b0:4864:20::112b])
        by gmr-mx.google.com with ESMTPS id q11-20020a056638238b00b0046e5105dd3esi240267jat.7.2024.02.02.08.08.59
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 02 Feb 2024 08:08:59 -0800 (PST)
Received-SPF: pass (google.com: domain of miguel.ojeda.sandonis@gmail.com designates 2607:f8b0:4864:20::112b as permitted sender) client-ip=2607:f8b0:4864:20::112b;
Received: by mail-yw1-x112b.google.com with SMTP id 00721157ae682-5edfcba97e3so22944827b3.2
        for <kasan-dev@googlegroups.com>; Fri, 02 Feb 2024 08:08:59 -0800 (PST)
X-Received: by 2002:a81:441c:0:b0:5e8:92f9:46e8 with SMTP id
 r28-20020a81441c000000b005e892f946e8mr2730296ywa.30.1706890139331; Fri, 02
 Feb 2024 08:08:59 -0800 (PST)
MIME-Version: 1.0
References: <20240202101311.it.893-kees@kernel.org> <20240202101642.156588-2-keescook@chromium.org>
 <CANpmjNPPbTNPJfM5MNE6tW-jCse+u_RB8bqGLT3cTxgCsL+x-A@mail.gmail.com> <202402020405.7E0B5B3784@keescook>
In-Reply-To: <202402020405.7E0B5B3784@keescook>
From: Miguel Ojeda <miguel.ojeda.sandonis@gmail.com>
Date: Fri, 2 Feb 2024 17:08:48 +0100
Message-ID: <CANiq72ku9wsHtnPAh5G71Y_pbsftrPPyV5wmDCcZRM+WB6KVjA@mail.gmail.com>
Subject: Re: [PATCH v2 2/6] ubsan: Reintroduce signed and unsigned overflow sanitizers
To: Kees Cook <keescook@chromium.org>
Cc: Marco Elver <elver@google.com>, linux-hardening@vger.kernel.org, 
	Justin Stitt <justinstitt@google.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Hao Luo <haoluo@google.com>, 
	Przemek Kitszel <przemyslaw.kitszel@intel.com>, Fangrui Song <maskray@google.com>, 
	Masahiro Yamada <masahiroy@kernel.org>, Nicolas Schier <nicolas@fjasle.eu>, 
	Bill Wendling <morbo@google.com>, Andrey Konovalov <andreyknvl@gmail.com>, 
	Jonathan Corbet <corbet@lwn.net>, x86@kernel.org, linux-kernel@vger.kernel.org, 
	linux-kbuild@vger.kernel.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org, 
	netdev@vger.kernel.org, linux-crypto@vger.kernel.org, 
	kasan-dev@googlegroups.com, linux-acpi@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: miguel.ojeda.sandonis@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="O+Qpc/P6";       spf=pass
 (google.com: domain of miguel.ojeda.sandonis@gmail.com designates
 2607:f8b0:4864:20::112b as permitted sender) smtp.mailfrom=miguel.ojeda.sandonis@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Fri, Feb 2, 2024 at 1:17=E2=80=AFPM Kees Cook <keescook@chromium.org> wr=
ote:
>
> Perhaps I should hold off on bringing the unsigned sanitizer back? I was
> hoping to work in parallel with the signed sanitizer, but maybe this
> isn't the right approach?

If you can do anything to keep it in-tree, I think it would be nice so
that others can easily use it to test the tooling and to start to
clean up cases. A per-subsystem opt-in like Marco says could be a way,
and you could perhaps do one very small subsystem or similar to see
how it would look like.

Something that could also help would be to split the cases even
further (say, only overflows and not underflows), but is that a
possibility with the current tooling?

Thanks for working on this, Kees!

Cheers,
Miguel

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANiq72ku9wsHtnPAh5G71Y_pbsftrPPyV5wmDCcZRM%2BWB6KVjA%40mail.gmai=
l.com.
