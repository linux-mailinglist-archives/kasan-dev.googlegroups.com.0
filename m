Return-Path: <kasan-dev+bncBC7OBJGL2MHBBTX7563QMGQEU4CB6VY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 090A698BEA1
	for <lists+kasan-dev@lfdr.de>; Tue,  1 Oct 2024 15:57:36 +0200 (CEST)
Received: by mail-pf1-x43d.google.com with SMTP id d2e1a72fcca58-718e065f057sf6783547b3a.3
        for <lists+kasan-dev@lfdr.de>; Tue, 01 Oct 2024 06:57:35 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727791054; cv=pass;
        d=google.com; s=arc-20240605;
        b=QSzlWiWNvMIoNk4y066PslyqNTz1hKh9cmeElocULue3Xl+i4kcJ1bwqH29PgVodLR
         R9syQLPX2UDVaXWU5gzWeUW1uOHgf04WlthX9xF7zJFf7TZIGFjP2LTEep/aOtms8ppx
         7sv3CKZWAcDdA5r4ayS8dTPWZPUgDA3nFyNolZtsbmmx/eN/E2jBO1P1gBAodXItM5FI
         LoK5rhEMFExohS8sx7Ax30ZQZDhxZZr/oCU54pCB68XrG76nGL1YVcsjDxW4FAuoZq80
         3bPt0gvN4ySuZEQ3ipeZYJxXZbjwOs9Hl+cRCHVf0ZRpmQz7rbmJqRjUGmC/zml2YgfL
         cNuw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=lVv46etWQ9VvdBe4GCgwUtSgk/dPmRXsLut222n6RCE=;
        fh=rdGzbCim4pWCtjrtkcKJHhLhnwOWEgGznlr7qcN1m9w=;
        b=KeeqmhJ/92+ayEPFE/Iepq3vLI/7+P3flDWOZCO2yVwrBApWDTAM5E0v8vbzUxEWfo
         IDC0uXPo/EeEhrK5lf1rNUZaDJf2xhCrQmXgzckHQ2Wqc9rNBNDpKxGFUwFjkWt0LK1G
         KOTYkmng4x/BV1eZ/FjGLo8JTAUG39eHG8GrsVlvMrU030YEuPxKcNskfGTN+D0vAWwq
         IOzSpzhXdKhxnKvCcGpzXSfj3DRzTM3wz27v1YV9aGwKQXZRs2kcGmPNVLHDQZP8lNAZ
         KVW2VkA0SL3MOx4pNKi8ds8mSXJ+Nm1wCRmJ7DqatgwijpzmPLI23mIXfGgk9ngRA4HN
         2mtg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HRbRYtTa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727791054; x=1728395854; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=lVv46etWQ9VvdBe4GCgwUtSgk/dPmRXsLut222n6RCE=;
        b=i+VRodx1k2LslXxRUp9+6ARBk0joLgXTn5PDZ4/JDGQe21X/Uxjh2cKGlUIdiI6988
         Hca69FBK6xZgzlRbYmapPrfLRdGJXzeK1kxer3NdzJou9UrHAaQ/mSDSOrpU3T9DGufF
         fihaP4G7eYfHfoICR/93arw450hdw4b3mc7JLxUkxhSQWzqClQimC0OQtAFh7+wDxDyh
         avjmo0/WlpJzrLvCDzF4x+35FKqhTk2ZsXspPXboZeXWDXOp6Fpy5mEfl73L7sgMBHxU
         1aPeL2YUTh0764PnGY/+3knnrCIhCV/hZjik2EoLgu3z6YCI/fIQ8LcBXS0jq1aTnzND
         BGfA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727791054; x=1728395854;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=lVv46etWQ9VvdBe4GCgwUtSgk/dPmRXsLut222n6RCE=;
        b=KdxTbWbD4eXmBrqVICtzjR1fqwUOFTG98m+f7DicObw80tJQg/r52t5pzXloI5Pouf
         ORjEV3crxpggqbyc8ULTRdc07uurS5XTz0bGQKMrVZIEQpOZoHejd5sYVItvOZeqputR
         vrSfAI9dZBQnF+zHoFzfnTzB91LjUzufvqaOv10Wi/SRJN20zvu26czDieHWm8rBUlNN
         1LlcLnK7MswoNScXDWPONAMrq9RwNkVvHCK3W/pNc34+u2py7YMiwhpdOVbcj60B4NxI
         bN7C430mw416s4lB5KknDsHaQtdpVVXmTOHzyBwKeE3v+PmUbT7bAQQ/ZF+nJWkc+OyK
         bA3w==
X-Forwarded-Encrypted: i=2; AJvYcCWQBshw6kHhuP+apl3Gx0Rjs2Am1S3uTSj9ddlv7caYXMXuvOMyQwd18tly+HJAjW5E6ANd4Q==@lfdr.de
X-Gm-Message-State: AOJu0YwQRBNQ0Bjv4MohEGvVWBcXaPEQ+Aq0q3N53gwClZXVCQyrD5GQ
	lsdgTKNPbFuuCtSK6TZ5qRPb5Gt/hOSzje9OgaQj2k3ikhBJZUOF
X-Google-Smtp-Source: AGHT+IHw48/NtT2+5+yBq/0yWDsxU7cfBKXuwr9lVZUpru9CUaAK4wVcP7X78UUDGejSJDUl3Iex4A==
X-Received: by 2002:a05:6a20:4ca6:b0:1d4:fcfe:e1ee with SMTP id adf61e73a8af0-1d4fcfeee5fmr15477687637.9.1727791054290;
        Tue, 01 Oct 2024 06:57:34 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:23d3:b0:706:6f90:b106 with SMTP id
 d2e1a72fcca58-71b18ba1241ls2321740b3a.0.-pod-prod-07-us; Tue, 01 Oct 2024
 06:57:33 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXzOB2U68eFhbvY1pF0JN/nQ5iIKpabQBXh+tGWkaSnynIS/Rm6hJlxf1lNFeZvJGzkL0O5UK3lp0c=@googlegroups.com
X-Received: by 2002:a05:6a00:1143:b0:717:85a0:1ddb with SMTP id d2e1a72fcca58-71b25f4419bmr25372344b3a.10.1727791052962;
        Tue, 01 Oct 2024 06:57:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727791052; cv=none;
        d=google.com; s=arc-20240605;
        b=MFcOBfyUJd9ojQRq9iyxQCq3nKl85zC1IvLMvokQW9ueozZCa3R0XRcehYEoiRLa9l
         W9PCkC3XAFyvz54wysYT+JCwEY05rWTS1ONDAgXeSYCK2puZVU6jv6m3E92L/R9g6tlh
         6hpKUIUTgnw0jZNd4YdA3kfZMyYEDkVwTDX9GgyhHYKPiPZGZKl0nWIS+nLZYDFwg5S7
         LCh/b2RzhXMbrlN7GU0Rf5ne1ormbK2h+vuocYigr35rBRZ0Dfx05OSV1+bbVwLy5YUO
         A/F02IQig4gVGNdeHhWj9EDdQZYSGMzsjIBeDB+oCCYdckhrELsQGMvQnySvdFvzODam
         XziQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=tm1ppOKwkqYM3Q0iCzaY7eJ6v95Qi/bldW5pozjAkbM=;
        fh=EIz5gx/HSmdUbD2golY3/tB8SD5SQ0KDGlCTPtMo3pQ=;
        b=HlT+C7Xzzh2y2f2s1hcF9+5ry3bDymxBHQGOIoqMWrUIhusfXzq1XXfjmnhwc1AKTy
         nroEBXcdSfNAgzdonFHaPnZFyNnoJwMrYOYoEXWux5sQKmBUfyHQ9wjTwAXd6Gv92By9
         D05SzGZQTDzhl6ERYFAaDhydUfMPvRZTmHAcm/SA8LJ6TUBzybJctyQfnhFu8qk25lFE
         RTCQeXiQO2ntIzdgiSa2knJztdHjCf5k6ZK/xaMCD4u0itinS6PdjrK6+nOEPMzhen6E
         fK1toxr8hOKF6iLWZlOo1Q+6noSvsb1tE6XR9Btu+fkEiaIyK+GUp7XPWFjHgy77QLXO
         3qmQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HRbRYtTa;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-71b26558952si492338b3a.6.2024.10.01.06.57.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 01 Oct 2024 06:57:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-20b86298710so20876565ad.1
        for <kasan-dev@googlegroups.com>; Tue, 01 Oct 2024 06:57:32 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCUZ3CvfhAc09gl9nZmrWc/PvW/B04gfLC9/TrFhU6J4bqlcFKIFo2NDJ58ZeHR281Xm2Vyf3FdgRnY=@googlegroups.com
X-Received: by 2002:a17:903:1ce:b0:20b:6c3c:d48c with SMTP id
 d9443c01a7336-20b6c3cd8e6mr101872895ad.42.1727791052220; Tue, 01 Oct 2024
 06:57:32 -0700 (PDT)
MIME-Version: 1.0
References: <20240925143154.2322926-1-ranxiaokai627@163.com> <20240925143154.2322926-5-ranxiaokai627@163.com>
In-Reply-To: <20240925143154.2322926-5-ranxiaokai627@163.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 1 Oct 2024 15:56:55 +0200
Message-ID: <CANpmjNNQUQU-jG6jzwVP-4_VBO0w8PVgA137pS72unhFc1k6hg@mail.gmail.com>
Subject: Re: [PATCH 4/4] kcsan, debugfs: avoid updating white/blacklist with
 the same value
To: ran xiaokai <ranxiaokai627@163.com>
Cc: tglx@linutronix.de, dvyukov@google.com, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, Ran Xiaokai <ran.xiaokai@zte.com.cn>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HRbRYtTa;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::636 as
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

On Wed, 25 Sept 2024 at 16:32, ran xiaokai <ranxiaokai627@163.com> wrote:
>
> From: Ran Xiaokai <ran.xiaokai@zte.com.cn>
>
> When userspace passes a same white/blacklist value as it for now,
> the update is actually not necessary.
>
> Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
> ---
>  kernel/kcsan/debugfs.c | 3 +++
>  1 file changed, 3 insertions(+)
>
> diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> index d5e624c37125..6b05115d5b73 100644
> --- a/kernel/kcsan/debugfs.c
> +++ b/kernel/kcsan/debugfs.c
> @@ -142,6 +142,9 @@ static ssize_t set_report_filterlist_whitelist(bool whitelist)
>         old_list = rcu_dereference_protected(rp_flist,
>                                            lockdep_is_held(&rp_flist_mutex));
>
> +       if (old_list->whitelist == whitelist)
> +               goto out;

Why is this in this patch? It seems like it could just be in the previous one.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNQUQU-jG6jzwVP-4_VBO0w8PVgA137pS72unhFc1k6hg%40mail.gmail.com.
