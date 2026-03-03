Return-Path: <kasan-dev+bncBCCMH5WKTMGRB7MHTPGQMGQEEMTQMHI@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 8MTdIQDEpmn3TQAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRB7MHTPGQMGQEEMTQMHI@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 12:20:32 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103b.google.com (mail-pj1-x103b.google.com [IPv6:2607:f8b0:4864:20::103b])
	by mail.lfdr.de (Postfix) with ESMTPS id 2E52D1EDA63
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 12:20:31 +0100 (CET)
Received: by mail-pj1-x103b.google.com with SMTP id 98e67ed59e1d1-35845fcf0f5sf6150662a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 03:20:31 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772536830; cv=pass;
        d=google.com; s=arc-20240605;
        b=Cq7dcSn+CsuPghLKJAHgurbe7nh/hnjswMdGnWJZBdaTdRM/nn0ZO6nwdoVasrgL5Z
         yQoTkq30sY8YdT/x92M/ghCuH9saJIcWdEQOoClFleEz1ZTE5udX9d9Lv63WqMcZysi/
         kE8Eu/a5S/fxeVV+KeYFYsIAxduSUFQzYTZ+7Sqs63evbUt+xe3Ffuh51cZOp0EXZGAI
         heNAn7PxlhQSQd0zEeSoKRKv2wQCqlD43kLpcW/tnefgbKBqp48TzvfqWxmteJSmSWBT
         Zvo0+CwMX8YeN1kE28N6/KsySZHK2wY9ZZ5aOePyjECUm+y0MX9wT7apH/UGaYWQjQRj
         2aeg==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=iGGF26zqYI1+BsKRevoM24G5vCyMdfvI2q3oqCPDEvE=;
        fh=QptT0eJbe0qRqDeQ85ApEMgYoHKhkTMqZ6hsDDcIGhE=;
        b=AaiydgecdizZGGXXht4NSzrbG61l01qFs4NUpxVumNXiKASqfMkOIsmX865c96QJZE
         W18LuI0xxw30lKKL/jyf8tnX3tUXzqU7kkJDag+dGpxpM1qxlytQN9scl6DqP6kNRUsO
         f+jhaCQfovJU/N1KhRLZ4HHrY86RQ/szds4ku3mYJ5WOHsHCKzrtNVKGdizWC8zcVvPW
         vqRHz+fQFediL/Ldj/I7fVx+uWiwjkyxtYE4R2qVC0QlwE5afxsmFs6aH3iKOo9cHVn5
         GN8Rn5foqzWAKSeOd0sBjzoRjUIzuNxb0vjDBX5YaP/Aa8eSIrIWmrQgABaAgZgJjnH6
         8kSA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=obBVoVmL;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772536830; x=1773141630; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iGGF26zqYI1+BsKRevoM24G5vCyMdfvI2q3oqCPDEvE=;
        b=ar6iXSdEjqhzH9iDRMSBw7n/4OyLDnfRyCYeytYvHoiOmXAOv8ub0f3ixbAa0vaVa6
         YyW/eemtulRR/DL2w+JBjUwHMNZp7QVSoaI02yL9RNXwcHCam41WEFwVpfW8+7/zeFOO
         iXWalkoTOAW/4ATHiDdq4J9ASOiwSNz9k/JM/CoOZpHQRbE9ioR/BAsg6im3YADIxLpd
         CGkZZSehwY4DmQVaNyBjHKsOdyCRzPSwCqoT8f7JIHVgCOL8BFirifTiyjGAUh9SjNsA
         u8asinZ+RNO7vA0zRShNvH8H/to5LwputYB42ga9Lf0OYo6dtNQb9N0hvoAQtu/0KpEP
         ta5A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772536830; x=1773141630;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iGGF26zqYI1+BsKRevoM24G5vCyMdfvI2q3oqCPDEvE=;
        b=SEfxwMIvPHqSfqnkZ+Qmu3jKJ2Q3ijjRikbbQpAlxtlwhkF52LwO4eaMy+PxlRZ2O5
         9HusjVYbSRwLE9+3TP61/QlFByAzWgI5uG81+XUNu64ta90tdpIrRkl38u+QYUzqEkD8
         dZrXDbUWbTuFq5+Rto/CxlMYRQnxCCCWG7Lq9xzDUGBrUVvIE7iCMmPoh2qb2HqytL1x
         v1LX99zLkqdvKoH05c4qzPEEL7LjApCxz83SepY2kjt2qyl5mcWJ5/auT61Uk3fYjQx7
         lFNxfDPjlb761Cj0j/Hr6adjiGZ+ukbIO8JDAa+Jv44b6QJmBOdmGQaxf/b3SR278sOS
         kHRA==
X-Forwarded-Encrypted: i=3; AJvYcCXP4iicgZRsVN5hqijucFsXakcRAn8qYwLyZXMJpU/aPZxpafynXf2Bx5zlEe0oXA4Ic9u9Rw==@lfdr.de
X-Gm-Message-State: AOJu0YxuxF6rUqKBo1L0PRxX4I1o33vhhs3s98E/PWoSp+gSGwIk8cWI
	OBisIMAzQ3zmjC+VDeZqLwg4V5c5uZ0bo6xHqAtB3YpKT7QULn4ZV26L
X-Received: by 2002:a17:90b:3a90:b0:34f:6ddc:d9de with SMTP id 98e67ed59e1d1-3599cefd783mr1552377a91.16.1772536830164;
        Tue, 03 Mar 2026 03:20:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HrWysxpojmDRjPmOzvQ/AEAot8Oxw6Dow8rdBMMEybJg=="
Received: by 2002:a05:6a00:1a8f:b0:7b7:c95c:8da2 with SMTP id
 d2e1a72fcca58-827137ead81ls3629348b3a.1.-pod-prod-00-us-canary; Tue, 03 Mar
 2026 03:20:29 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVuiOB5IJ5Vry+9pipqidyacZFbdBXdRygj5MltweaH5Q5qreXvgPYaTreroGunA0rOuYoCr8mqT0s=@googlegroups.com
X-Received: by 2002:a05:6a00:2e25:b0:824:a466:7470 with SMTP id d2e1a72fcca58-8295d9593cbmr1911053b3a.17.1772536828661;
        Tue, 03 Mar 2026 03:20:28 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772536828; cv=pass;
        d=google.com; s=arc-20240605;
        b=dkl5xCjuQ2cpWJUUqdF63Pw4gCg+2g9M2jyDDI3B50eRPwcJ9JK3cTkyQkJxA7hTa4
         yu7spKYaes7MXzUzHbK3DpGjVaKnPA49ZJdauaEEfR6Et5Bxw9fHsv5/u2YAMIFjLz4T
         QqeV6hDzVr/wUbV7fPKnqlO/+MXbyh3TW7c06+vm+Lxn0+iZ7kbaV2blhjo0tLzrePcN
         QTwDKRlDf9KDNVKCc7HDRh+vLrLFILqW1mleW9I5s5jG+oAEd99ZveW0b8JUYuigBCDL
         H4sPtZUm5qEJ8n2d7XP/XXJB0kRCBoAZvsyXjs2KCL+TtxJ7HSnJhXOLGAZ9eURDaWBS
         Izmg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fs5xy54dOwpapJM1ABjgdm4o/gqygsmCGVNWqgWoRQE=;
        fh=4j+CbTVRp8v8h/aXXry2sy/zjUkwoN2UYhahWCWukKU=;
        b=LycEdM0m+12jqSaXsCXjQsZSENSRxn8Uhb7ClwKAXB7fcJSqRmruyUpJtfHbykHcZ9
         nqtjL4q2x/hu4Ic1xDIuKYC+sz9K1wwA0IDwU7Dl9vhpuKAtAR/5DIQl7RAiW7wBpZcC
         lwztQyAB/pOpMzFwqzZKesM0OGeCNvofJNi354aRDkvFHwqz1mlBN7FkAGv+krShwvnJ
         4HMoATEmwue1l7msN8EwSXqyBnjpd8AvTyg7ul+APLZsguoSQxLqzHcZkYpNT4ht/fB3
         vvkPva3KbBf0PKZTq2x+Zlf9HqMddd+mdnym6vz4Vd2N4F2K5GKtlCTIhdgcCohk0e+J
         +KtA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=obBVoVmL;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf30.google.com (mail-qv1-xf30.google.com. [2607:f8b0:4864:20::f30])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-82739ffe9c5si487172b3a.1.2026.03.03.03.20.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2026 03:20:28 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f30 as permitted sender) client-ip=2607:f8b0:4864:20::f30;
Received: by mail-qv1-xf30.google.com with SMTP id 6a1803df08f44-89a0ecbc713so4281076d6.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2026 03:20:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772536828; cv=none;
        d=google.com; s=arc-20240605;
        b=abdfanAiYdIlaxnkcobEs42FnPRaS2cIVS+fs/ZFbeHzmux+8c24+fyE+aJbudv+ia
         YyJwNahg9EmgGMfhepnGDuGOBUQ+Kl2UDACWG6cfF+wEqy2VEMNNtD5L2c/t3HdQV59Z
         w3bx+7gBqWdxt88skm8HTjNyLAxRxHKWCga2ET8VMKWZGQPxZf8lw3wkEH72fRewOpjT
         01hGrey0LXWOv7iNGJ/J4eELCjBLzdvkJ3PsloPYqbUsIvwTaaElzotyQfs7YS//mwC5
         1wBlyZMMSuGYUP3UQ0pKVinO4eWW5/T6Kt72ybNWDVPn3hbEhaglv/l5Mx9PIVCfnD3m
         L7eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=fs5xy54dOwpapJM1ABjgdm4o/gqygsmCGVNWqgWoRQE=;
        fh=4j+CbTVRp8v8h/aXXry2sy/zjUkwoN2UYhahWCWukKU=;
        b=eDhkuEhf71I5iGQSrGfHbmQSn000tAZ/Ovu7MuzdDR2Hy1gLgPPjuFdZB5X/yvf0Kn
         fITA510hvBMPwYOWQGCbYx55T8/NkHxpoSd5Tbg8LSOrY6e31O9S8pcCNl1nBhQRd6U/
         Rf74QsxZpgeEscynvS3NzBzE+g6ZL0+w7dBSzOyfeh0IAg2JuC1pP13Ol+b8bxWHWbFN
         vPOptKYl7AyunrL16puZPxvV1qMoiwP5gp/DXLPgK2AopH+UhXo7xXgCC/Hf8LEZC2dC
         qjvepsKjf51OiIBua/rNe9ZMdPXljGixBjosoAwP64RvvRreF7sfXA6AKdtftV2ahQYJ
         qOMQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWBJErnXhgDQHu/666buT4K4veO77CV9JgrLjN/6q/uWSd/u3g7qCVuOPXglGmfE3h8VPf2mLiggJU=@googlegroups.com
X-Gm-Gg: ATEYQzy9ayflNNX/B7GG+0/2hMDshSG0J4yrHl7br0SapOX9K0PwPlaHSiVD96exqyT
	OSHecch7VskUYM0aWxEL1aHKSEbMN965F08Db+tN2KzRhPcOIbDmCMm/QnYAKHSNu8LArTzvSi7
	Sw4bjZ/ItixUtvv8dpnX+YsUoO3cM0oSgyge/ZLnA2dgwbf5HU5Ap0wF4Lxth5sK7yg3QgNsJff
	i3xb72eOnBmlSeRashcYRaKpY2eIs0A/UCiL62znchEOT1GzBVHzpjoDcoBH7Sa93bEJudkom9c
	EKcFIWdMGLtMQAUiN9PwRTHFFeHMVSRSSbykIiYu1TW4rjQl
X-Received: by 2002:a05:6214:dac:b0:895:4d3f:b6c with SMTP id
 6a1803df08f44-89a0a89d396mr19056596d6.17.1772536827672; Tue, 03 Mar 2026
 03:20:27 -0800 (PST)
MIME-Version: 1.0
References: <20260225203639.3159463-1-elver@google.com>
In-Reply-To: <20260225203639.3159463-1-elver@google.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Mar 2026 12:19:51 +0100
X-Gm-Features: AaiRm51ecwm2GzpvBNPquu22Ta0sfwGcKpcC_V0mxDSrZBLMaa5eBCNTn_slx0E
Message-ID: <CAG_fn=WAwHUpoay2kY6rkEZQGYxoDGVJYf5B59Y80ht7++Lmqw@mail.gmail.com>
Subject: Re: [PATCH] kfence: add kfence.fault parameter
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Shuah Khan <skhan@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-mm@kvack.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=obBVoVmL;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::f30 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Queue-Id: 2E52D1EDA63
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[12];
	MIME_TRACE(0.00)[0:+];
	TO_DN_SOME(0.00)[];
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRB7MHTPGQMGQEEMTQMHI];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[glider@google.com];
	NEURAL_HAM(-0.00)[-0.999];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

> @@ -830,7 +835,8 @@ static void kfence_check_all_canary(void)
>  static int kfence_check_canary_callback(struct notifier_block *nb,
>                                         unsigned long reason, void *arg)
>  {
> -       kfence_check_all_canary();
> +       if (READ_ONCE(kfence_enabled))
> +               kfence_check_all_canary();

By the way, should we also check for kfence_enabled when reporting errors?


> @@ -1307,12 +1314,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
>         if (to_report) {
>                 raw_spin_lock_irqsave(&to_report->lock, flags);
>                 to_report->unprotected_page = unprotected_page;
> -               kfence_report_error(addr, is_write, regs, to_report, error_type);
> +               fault = kfence_report_error(addr, is_write, regs, to_report, error_type);
>                 raw_spin_unlock_irqrestore(&to_report->lock, flags);
>         } else {
>                 /* This may be a UAF or OOB access, but we can't be sure. */
> -               kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
> +               fault = kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
>         }
>
> +       kfence_handle_fault(fault);
> +
>         return kfence_unprotect(addr); /* Unprotect and let access proceed. */

If kfence_handle_fault() oopses, kfence_unprotect() will never be
called, is that the desired behavior?


>         /* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
>         if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
> -               return;
> +               return KFENCE_FAULT_NONE;

We explicitly don't panic here; guess it should be fine...

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DWAwHUpoay2kY6rkEZQGYxoDGVJYf5B59Y80ht7%2B%2BLmqw%40mail.gmail.com.
