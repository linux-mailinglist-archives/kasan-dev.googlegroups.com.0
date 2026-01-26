Return-Path: <kasan-dev+bncBDH3RCEMUEHRBKND37FQMGQEFIEIA5I@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id 6MzOIavRd2mFlwEAu9opvQ
	(envelope-from <kasan-dev+bncBDH3RCEMUEHRBKND37FQMGQEFIEIA5I@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:42:19 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x237.google.com (mail-lj1-x237.google.com [IPv6:2a00:1450:4864:20::237])
	by mail.lfdr.de (Postfix) with ESMTPS id 11AFB8D339
	for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 21:42:18 +0100 (CET)
Received: by mail-lj1-x237.google.com with SMTP id 38308e7fff4ca-385ce4cf13bsf1174181fa.3
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 12:42:18 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769460138; cv=pass;
        d=google.com; s=arc-20240605;
        b=gm9E2TistwAS1OkJp7KUuyMnHOWUotF2dr6Gh0GcPwrLfM4hmYRA0FD3eZuLo5iMY1
         HJcxNfHLyUBWPXfkJ69Hhi+rIjshu8OcqddDef2JF4E12r48KSIHM2lBS3wnB1gL+Aup
         f96T2r4ZLPuRXtB40RtZIkPn1oMBe7ZYLp3qiT9OTqhhD4J5pagrVD8nqXbxs4FVO/Il
         js1pFAA5RF7t5kt4OAzwcQAMVSQgSy7kBAWCBhhfrMLJ7hO+2Ns58SKYPK1Ssu3qBYbI
         E6ZcgNAjB6nzEufVPKQtWVcsziZYsVwsRuRE43vmHlfUxwFD2g1/b8GnGeMsx1UWx/FM
         7agw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=iFeBrtnYOf3kV5B+uXRWOi/TTata2EC4So2eYq7qc5U=;
        fh=C5spcPUQjqzcDCWoPciSV1wK/mMXomqZNkl8bqIe2wg=;
        b=gBmSU9YvHn7ned5b4d0pIYDR1dZ+dYHPFa0uzVBGubqUGEnA2g+Oj6r65SUXqKF70n
         zqTzOy9iYQd40eqTUBt57aaYaFwi0rfI8wy+VLhPIwxxHtNUiimMFinyA7ky5MqbTZke
         E3kAz6qhJ/6+p/MoLFuYzyTHVTodJ8Fwm/yS0DX2aZNsS7roHkqzJrl2nrKJ3+PBLtu2
         y6p0D5DkgSH+W387Jkfd4FwKfD6n/aAK/D+46nMkzp6remTj29GmACfgyW/+Kx/hXPvD
         cTyZ+129tNB37a8YY5+DRNp+1U7cZR4JJUzhdsjxhan3L+fPtoYYaKR9FiUPbixZ9H+w
         U7zg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lURr7MCX;
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769460138; x=1770064938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=iFeBrtnYOf3kV5B+uXRWOi/TTata2EC4So2eYq7qc5U=;
        b=RTl5XzgcG7STuS6rVGqfscPgSZ3BXglrTWJD1LNMNQxxvTgntFm+JJgJFT2OC02m8m
         PZrYenAbom41QbATZoQdvxfJl7dXVYhImWf+8gip3rUq3AgpPkIypwhWm0BeHRQZcVjB
         py9sqCVpBVeXW5jXcHANU4u/kwUaFAc0NB3QtAkpOYFBeBhqPf3g1xWEsZg0KlJg0bF4
         d9dgy80mr3WBm4uiiF4WOj/7+Ppz9ugUYj49ysz9x8eF9AJ0+s2XtnAL5FCcxodtUVb1
         mZmDwCA+/W7gxHe+5oTDsEXZD+9hmYfzdHJMnvMde3G1UWnFmnXlLgFMCwgnVaOSm29R
         wn/w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1769460138; x=1770064938; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=iFeBrtnYOf3kV5B+uXRWOi/TTata2EC4So2eYq7qc5U=;
        b=DA3o7L+Ia7KdO8eptmOZWdQHAeIBxn5eIk4laV7GYHzH0IKUIgNdLLRkDNYhd8lCwZ
         OB3lBwEhh8DbQTvCa/CxW8dWWweMwoBzkeU6NLcV9xtp/mY7mgQe6VChF6TtGfjRJdeN
         W2ajoC0uQZDOBRqNjp+jAJhZn+k72YqC3Z3TmridI6ZWJhozjhaCA0uID7xvqTwI72OE
         wOZUZtDMJwTIlBsZu5StoCol19SgegnY8RQlbRq9SxgesLppJaFfmWLa1pCNy0J0kMpJ
         Pj3h4IlbqemWw3kCMh6ysV9LilbeuIOXrWrP+bwGd2Ym6/l3hIkGc2UXBzz0xFhGONnn
         ZW4A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769460138; x=1770064938;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=iFeBrtnYOf3kV5B+uXRWOi/TTata2EC4So2eYq7qc5U=;
        b=cd6ufzDxg84WjCDmP2cQyozvxPFcvlYe4NyHnooYuW0GShj/ENfWsv0r3O9DV7bzCc
         QafTpVQJ5d3x5YScq/pyBn0gIVgeFh6EUc3DVetbrIPW9QnchSk9BsF5G5vfjq98CJDA
         6PbSEZzIIIQ54qpseGeuay9/ohRB20kL3IW+kPDMHBb4OyOeRJAo6ehuiR6wog5a4YZs
         PPLna6yN2KTAB2nTzna1uiKLotTlko/3VwxCtdWjR82ZCUv7r8SGtX3Hs3j3XPDfONqy
         j1UlyhI9iNWCReVRz7/patQlfUpAiFfU6ti2WF1bu5LMHOKOJkcoSZ54waT3iCC1R1hZ
         FOIQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=3; AJvYcCWL/8zrTy8x3rVlw+T0wZM2tJ5PQAqVTg8jySpZtNAQMVmThRveTwgrPRzGvOGuFnmvM/31Bg==@lfdr.de
X-Gm-Message-State: AOJu0YxVSMIvLK3JAcX2X3aVUrGw0um5t1K+0hPUkaMlVoEg5bwWGMfi
	WXCVJB8GOuoRasbZtp4nEA3xh+xBFDrf7N/rPdcr6hAjC1aSB08D0u1I
X-Received: by 2002:ac2:5694:0:b0:59e:69:22cd with SMTP id 2adb3069b0e04-59e00692465mr288785e87.2.1769460138076;
        Mon, 26 Jan 2026 12:42:18 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GScfyo8vLnYlxA5TuDV3+eGuZcbsiJlJmKllt5fZNDDA=="
Received: by 2002:a05:6512:138d:b0:59b:7bbc:799e with SMTP id
 2adb3069b0e04-59dd797ab6als1690202e87.1.-pod-prod-04-eu; Mon, 26 Jan 2026
 12:42:15 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUzwooLrXiLx5/edUL/+eD4HUvTcpKuSmzZCXv92IaoonYtwwPOZ5Mf7rQ9mmXBaRCs5YLovdcJbF4=@googlegroups.com
X-Received: by 2002:a05:6512:304e:b0:59d:f669:c924 with SMTP id 2adb3069b0e04-59df669c967mr1546471e87.27.1769460135052;
        Mon, 26 Jan 2026 12:42:15 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769460135; cv=pass;
        d=google.com; s=arc-20240605;
        b=LC2fB/Bm39CjIXX/1bva1FuUG5ruX8kUicueAjTcFcTBICgfx3skiDTkYE803ecuCP
         HvgYyAGFNSZ2dUczRzJAtKks+idH3koaBU3bOdqRu0a3gbzl6lCRSO9IOKHXWSSGeTNg
         RChjOH6lhafALfmw60/ZRLtL/YZj1qI6JBmDdixSRYkKat5y2Y7akpyp2cneTWdMp33t
         yGgLxvtQABhVehC8Qh4tTE+yIQqPEwSazVfIha4u8Wh8zZGsw1eJUY6MgErIfwEBakDc
         eRuBabNdAfgv2Za5o2Ggbt5Dgl8CQRLeUr/+DzIKg++JjgpnQgjM9qq6V55lHgbD1Gx7
         7huw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+m2qkGL0qcz1nbB0fvdS8etkKTnr1dQAHlVJIgEFdqA=;
        fh=bPzIJ9s7BnPS57hfWkqV2LCz4ksqa2x+RPFB1GExsBU=;
        b=T+UhAdz8Rm3jfwJ6tCQuCVaN5/iX1rfQpJ2g6QChH0P6n2JLO++8TM9M2N42m+JVwQ
         xSiX9Td841x32bpprGPpRkJgvSTTHVb4oe7NYO/5z8vd/XWc6K0LEMgj3a3WQDuuqBcN
         PLOmh3jEUfURo0Phl0KmfiCepn7NNpX7v98KYKGGn3xOPP7x0BmQYIihGPlMypI1rGiK
         9329rzjT4q6pfvlmb1FpXqdorD2ZXW3JP96EQ/xFC2kzwhux8R9krabPEjnl0YUWcb9x
         Ds9M8fB1pcb3fYwitMJTlG7xIV6T0DpAeNt55myIoyvlrAgJijziDDcMSgiM6VRCyO1p
         PqQA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=lURr7MCX;
       arc=pass (i=1);
       spf=pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x230.google.com (mail-lj1-x230.google.com. [2a00:1450:4864:20::230])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-385da0e9ef2si2301121fa.5.2026.01.26.12.42.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 12:42:15 -0800 (PST)
Received-SPF: pass (google.com: domain of konishi.ryusuke@gmail.com designates 2a00:1450:4864:20::230 as permitted sender) client-ip=2a00:1450:4864:20::230;
Received: by mail-lj1-x230.google.com with SMTP id 38308e7fff4ca-385b6e77ef9so45470891fa.3
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 12:42:15 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769460135; cv=none;
        d=google.com; s=arc-20240605;
        b=AssRd2foI2OPFtK+YuU4mSLAH32Xer6/6Ir/8foC/sMxCKVVjDYQwhK4sv8+6mfTQK
         bqxbUHH8iJjwVfdL3Msjk1ajr9fN1L4OBpwYmMetDpx6gm0pmkmJKqpUaASJfcHteAC/
         MaJcrvpIUihQ6phSmXlJAltjeRZdVVajjkuvCSL4Yn8wftlf9WDZ9w+XEHqztN3Qhrqf
         pVPT8Dxxbl6/OggusWyYi2fM3zK1oNJSAVuI1N5rcef4x+KjtRnvZpr5RQuzAJ6tDy5e
         XwmwJbOXS4BNCZ2p8mdKekSLAw69F4+GSK5sIhNPygeY5GKi2x08sJRd39hl73OgfNcC
         SvNA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=+m2qkGL0qcz1nbB0fvdS8etkKTnr1dQAHlVJIgEFdqA=;
        fh=bPzIJ9s7BnPS57hfWkqV2LCz4ksqa2x+RPFB1GExsBU=;
        b=QYS3VuszK1q6qICdpuOxPlvFHMfV/4hqiT6yghbb/UCRSGU99xg0/6gSAC+aZZrNEe
         Xto4EpXu/u2g9pvD0Qeq0X57wXHpCzCIr1d7mWcUHZlBnWupF2XdEno8FJWEYKe0XLUO
         wN7X2smvs5gBGuoZtZ0qpM49wfWN1WQPovElASd18g0BxlnvryH/HNeGRrKWfAUZT/MF
         LmyN34LWPwUfvYfBe630PBUZNvss5iHMuxz0WYM9sYme9bxoQqtzdoo9Bc+FkYubAqT2
         09mRDpRqkGfaqT8dj6x23WwIQVbDyaTDiTeX8x2PW6qFGuyCMXkZH18D7RzFoSf7TUFA
         UWgA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXey2CDObtz0czbgkIeXHKMT0ltNK19aWJCrvwJqU6vp5R4LD/DKIZ3AlJiFi7MkGwbt6C120mGYKg=@googlegroups.com
X-Gm-Gg: AZuq6aJ3B75ZWuteuxvf3OQP/wxqSSkgPTpfrBUklCfYTxTGwyKGqIsPmXpMj0o+W1u
	eX3uxJkdivTUvay/qe1LS0lgI4YJFM1bhNIBmhzq7WSUd2iMt9WEQsb/kFjQ770OPztmEIOxZPI
	lYm0BpMvRP9BBt+hP/ARYcclDSNykAtHA3xlcMSfIAPEYxvMOUc2NSPCDwkYlHMf4agCFZvRC+h
	WKXcKYG5rIHOHkxqUoQI/ixs/oz/ukL5V9WZId/aK0fCYv/CKpln4mHSmtOPjK1EAhwtdG3
X-Received: by 2002:a05:651c:f19:b0:385:f6e8:1bef with SMTP id
 38308e7fff4ca-385fa142fa1mr16437311fa.23.1769460134252; Mon, 26 Jan 2026
 12:42:14 -0800 (PST)
MIME-Version: 1.0
References: <20260106180426.710013-1-andrew.cooper3@citrix.com>
 <20260107151700.c7b9051929548391e92cfb3e@linux-foundation.org>
 <CAKFNMokwjw68ubYQM9WkzOuH51wLznHpEOMSqtMoV1Rn9JV_gw@mail.gmail.com>
 <20260126195431.GDaXfGd9cSwoH2O52r@fat_crate.local> <6adad05f-bd56-4f32-a2d5-611656863acb@citrix.com>
In-Reply-To: <6adad05f-bd56-4f32-a2d5-611656863acb@citrix.com>
From: Ryusuke Konishi <konishi.ryusuke@gmail.com>
Date: Tue, 27 Jan 2026 05:41:56 +0900
X-Gm-Features: AZwV_QhVcyGvI8D6Iwxj0KgslXCRc0k5C7h1wQxYbWEYdDLGbCbFHpaRFydXWGg
Message-ID: <CAKFNMokFvcMdAfsvRy6JVpWGnr6BtqUOwH7nmyS=1K51HD1vYQ@mail.gmail.com>
Subject: Re: [REGRESSION] x86_32 boot hang in 6.19-rc7 caused by b505f1944535
 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
To: Andrew Cooper <andrew.cooper3@citrix.com>
Cc: Borislav Petkov <bp@alien8.de>, Andrew Morton <akpm@linux-foundation.org>, 
	Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
	Thomas Gleixner <tglx@linutronix.de>, Ingo Molnar <mingo@redhat.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, X86 ML <x86@kernel.org>, 
	"H. Peter Anvin" <hpa@zytor.com>, Jann Horn <jannh@google.com>, kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: konishi.ryusuke@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=lURr7MCX;       arc=pass
 (i=1);       spf=pass (google.com: domain of konishi.ryusuke@gmail.com
 designates 2a00:1450:4864:20::230 as permitted sender) smtp.mailfrom=konishi.ryusuke@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[gmail.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601,gmail.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2a00:1450:4000::/36];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	FROM_HAS_DN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[14];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_FROM(0.00)[gmail.com];
	TAGGED_FROM(0.00)[bncBDH3RCEMUEHRBKND37FQMGQEFIEIA5I];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_NEQ_ENVFROM(0.00)[konishiryusuke@gmail.com,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+,gmail.com:+];
	MID_RHS_MATCH_FROMTLD(0.00)[];
	MISSING_XM_UA(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: 11AFB8D339
X-Rspamd-Action: no action

On Tue, Jan 27, 2026 at 5:22=E2=80=AFAM Andrew Cooper wrote:
>
> On 26/01/2026 7:54 pm, Borislav Petkov wrote:
> > On Tue, Jan 27, 2026 at 04:07:04AM +0900, Ryusuke Konishi wrote:
> >> Hi All,
> >>
> >> I am reporting a boot regression in v6.19-rc7 on an x86_32
> >> environment. The kernel hangs immediately after "Booting the kernel"
> >> and does not produce any early console output.
> >>
> >> A git bisect identified the following commit as the first bad commit:
> >> b505f1944535 ("x86/kfence: avoid writing L1TF-vulnerable PTEs")
> > I can confirm the same - my 32-bit laptop experiences the same. The gue=
st
> > splat looks like this:
> >
> > [    0.173437] rcu: srcu_init: Setting srcu_struct sizes based on conte=
ntion.
> > [    0.175172] ------------[ cut here ]------------
> > [    0.176066] kernel BUG at arch/x86/mm/physaddr.c:70!
> > [    0.177037] Oops: invalid opcode: 0000 [#1] SMP
> > [    0.177914] CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.19.0-=
rc7+ #1 PREEMPT(full)
> > [    0.179509] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), B=
IOS 1.16.3-debian-1.16.3-2 04/01/2014
> > [    0.181363] EIP: __phys_addr+0x78/0x90
> > [    0.182089] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00=
 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00=
 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
> > [    0.185723] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
> > [    0.186972] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
> > [    0.188182] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 002=
10086
> > [    0.189503] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
> > [    0.191045] Call Trace:
> > [    0.191518]  kfence_init+0x3a/0x94
> > [    0.192177]  start_kernel+0x4ea/0x62c
> > [    0.192894]  i386_start_kernel+0x65/0x68
> > [    0.193653]  startup_32_smp+0x151/0x154
> > [    0.194397] Modules linked in:
> > [    0.194987] ---[ end trace 0000000000000000 ]---
> > [    0.195879] EIP: __phys_addr+0x78/0x90
> > [    0.196610] Code: 89 c8 5b 5d c3 2e 8d 74 26 00 0f 0b 8d b6 00 00 00=
 00 89 45 f8 e8 08 a4 1d 00 84 c0 8b 55 f8 74 b0 0f 0b 8d b4 26 00 00 00 00=
 <0f> 0b 8d b6 00 00 00 00 0f 0b 66 90 8d 74 26 00 2e 8d b4 26 00 00
> > [    0.200231] EAX: ce383000 EBX: 00031c7c ECX: 31c7c000 EDX: 034ec000
> > [    0.201452] ESI: c1ed3eec EDI: f21fd101 EBP: c2055f78 ESP: c2055f70
> > [    0.202693] DS: 007b ES: 007b FS: 00d8 GS: 0000 SS: 0068 EFLAGS: 002=
10086
> > [    0.204011] CR0: 80050033 CR2: ffd98000 CR3: 029cf000 CR4: 00000090
> > [    0.205235] Kernel panic - not syncing: Attempted to kill the idle t=
ask!
> > [    0.206897] ---[ end Kernel panic - not syncing: Attempted to: kill =
the idle task! ]---
>
> Ok, we're hitting a BUG, not a TLB flushing problem.  That's:
>
> BUG_ON(slow_virt_to_phys((void *)x) !=3D phys_addr);
>
> so it's obviously to do with the inverted pte.  pgtable-2level.h has
>
> /* No inverted PFNs on 2 level page tables */
>
> and that was definitely an oversight on my behalf.  Sorry.
>
> Does this help?
>
> diff --git a/arch/x86/include/asm/kfence.h b/arch/x86/include/asm/kfence.=
h
> index acf9ffa1a171..310e0193d731 100644
> --- a/arch/x86/include/asm/kfence.h
> +++ b/arch/x86/include/asm/kfence.h
> @@ -42,7 +42,7 @@ static inline bool kfence_protect_page(unsigned long ad=
dr, bool protect)
>  {
>         unsigned int level;
>         pte_t *pte =3D lookup_address(addr, &level);
> -       pteval_t val;
> +       pteval_t val, new;
>
>         if (WARN_ON(!pte || level !=3D PG_LEVEL_4K))
>                 return false;
> @@ -61,7 +61,8 @@ static inline bool kfence_protect_page(unsigned long ad=
dr, bool protect)
>          * L1TF-vulnerable PTE (not present, without the high address bit=
s
>          * set).
>          */
> -       set_pte(pte, __pte(~val));
> +       new =3D val ^ _PAGE_PRESENT;
> +       set_pte(pte, __pte(flip_protnone_guard(val, new, PTE_PFN_MASK)));
>
>         /*
>          * If the page was protected (non-present) and we're making it
>
>
>
> Only compile tested.  flip_protnone_guard() seems the helper which is a
> nop on 2-level paging.
>
> ~Andrew

Yes, after applying this, it started booting.
Leaving aside the discussion of the fix, I'll just share the test
result for now.

Regards,
Ryusuke Konishi

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AKFNMokFvcMdAfsvRy6JVpWGnr6BtqUOwH7nmyS%3D1K51HD1vYQ%40mail.gmail.com.
