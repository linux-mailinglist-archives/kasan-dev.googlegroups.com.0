Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV6R7DGAMGQEHWVMM4Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id aD3ZF9oonmn5TgQAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBV6R7DGAMGQEHWVMM4Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:40:26 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113f.google.com (mail-yw1-x113f.google.com [IPv6:2607:f8b0:4864:20::113f])
	by mail.lfdr.de (Postfix) with ESMTPS id E753218D7F6
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 23:40:25 +0100 (CET)
Received: by mail-yw1-x113f.google.com with SMTP id 00721157ae682-790afc07667sf99892877b3.0
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Feb 2026 14:40:25 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1771972824; cv=pass;
        d=google.com; s=arc-20240605;
        b=exHKx0b7lnkv/l9vvAjy4DKw/hZNNuiX8fzuVB+pfXzDRf1g1P4nWRukqQ8ZlCEU51
         o86QXK5VPfKM948hcOFYNbHlIDmGHCzlZ7GeE6YVh0GboaWNezB53Ia1W/9DzTkJjTvW
         CcBhoNhrXbi9ep2i0n8WVYP7AofjH3uKSRMf6svEsKipQPgTE0606/uiPLW7ESpAlvWf
         kV5J95T5pxsjiNtMd93xULL+QiuSqseZl7FzwD0sOs4f6X0AgJHEfAQ4leoD3x0Qo53S
         tAqyYhU3MCuXce2ZPQMcENNmZw1fwAGdKrwBvTiDUClHni8HZgoiT7+QwxWVNTIfb985
         g3eA==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=4gBprtjIGO9PoeJ5dDlIj3PQQDWiWv9KWk9DDSwAZ0k=;
        fh=0Mm0wImhpaTmnymvCqS4PHTBwCZDytxCcMgjycv7nuI=;
        b=WJZWsZQLOI3QMcV/V3t1kHiZHeZ+NUwL0JTzbSRxXea+4cvk+tHDh9uhclMkYdu+VV
         kP4seRulLj18L0tu66cy/4BDTy8xFQE/mZ0XUaUPQdvGXrC5LskkoZ30SNCuEO6YyYkd
         +58okaUh7NQHDR/eHY1/PFguI9kDxgfPR6h1qWvB4pMRO9kpmv8rCaw3D9ieWi1SgeaV
         hSij1JQJ5zu2Bjy5vxyu9AQe7fDlHGJWkg1A+NDZM8yANFF/DUNXK/Weri138mXh89sx
         wb2pLzjB8wo11FB0Q89yLx2TAvvFHTVXFQcW0X3GT3t4CF2xOYYATdPTIXAftN5LOpbo
         Mh3w==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UR5CB0Sy;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1771972824; x=1772577624; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=4gBprtjIGO9PoeJ5dDlIj3PQQDWiWv9KWk9DDSwAZ0k=;
        b=QGGuBIQ17MANy0thtxtxsJr27otraaCDG1IBHlx/4C5IW87j0eM8l7mg6jaPoqqUr+
         4P7R4f9NJ3fwwjx8KqHUnqsAWnfxjsNjC+8GKp5FwEaJ4ll0W99FoqWCklmC8eCK3iAw
         0wt72mYpkw0HWAft51TMKX56eUHRFUsUblW5pB6kQi84MKWnjhazK7gQ5/R68oAmZgDB
         B/7tpd78M1fDAdsVxxFVS2zqmYuYlWslCZCdKMtZ1/s4GckZkbiMmnXB6tN4Y3I67AJg
         SueglyNanzwc/GhuY4lo1IoI0+kosGLLCijdlBibrSomaq0woDRWcU/1Lfz8DDH4Ptqy
         Xc3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1771972824; x=1772577624;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=4gBprtjIGO9PoeJ5dDlIj3PQQDWiWv9KWk9DDSwAZ0k=;
        b=TuYrDdqdWVGnmnZicGunQZK/dbqWuIVWBC0JCy6upcD2PTMLQOUcRGmRPLQQZndSVK
         urLnQYMdSVg9WCJyR7GOieKtfOW3vYqG1Yq/42A6K4PhoHPofX8WnSgbJQoZ696dRI2s
         UQNmI+LkyffBHRYHBxfCjmWtjmb03JRRlln/kMJGFIfNG1VRrUuRprOvisSjthOUD8wd
         PM4Yu+Gpa8RFDD6UTCzcm1tOv+LezOTFTFxXa2Ng2na/p0S5DMCkI2BGVnifnpDy0yoo
         Ex5IR6MshacR85Ss6rBS1czT1AiOQX7pwy8pRlkYFaMuJcpD5WCbs9/B8n8AkAyG3Pkz
         sqKA==
X-Forwarded-Encrypted: i=3; AJvYcCXusEFONNvtykvpjUw8KY5QeM2CkUBi8iNfMb9nocot/IeDkNeu68Efg7fYcrc2ZTYcahSQMQ==@lfdr.de
X-Gm-Message-State: AOJu0YyX211mqZbIfp1sNymMrYEwLhY5vRsL0ilZoscYPdQh7Ozsu9G3
	owCp9pu25vFJ4tIZR1THBIPmc+AaikYizQrwZtZAtIVvrD61+Awu4LwM
X-Received: by 2002:a05:690e:144a:b0:64a:f1c0:65e0 with SMTP id 956f58d0204a3-64c7906c42fmr11477293d50.76.1771972824189;
        Tue, 24 Feb 2026 14:40:24 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Edtl0TqnPWK12o49dIDwL6CkBddcYFRy724pFIeB7AOg=="
Received: by 2002:a53:d752:0:b0:64c:9c47:5ce0 with SMTP id 956f58d0204a3-64c9c475e06ls1233138d50.1.-pod-prod-01-us;
 Tue, 24 Feb 2026 14:40:23 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUXCtzemwkM7c8CnenawljtNC6UG03a3HFo20MjwIDM7laLC6ETgDfJMS1EAcmRvVePV9GnBuelD2E=@googlegroups.com
X-Received: by 2002:a05:690c:c4e3:b0:798:6401:fd31 with SMTP id 00721157ae682-7986402008cmr18379907b3.15.1771972823103;
        Tue, 24 Feb 2026 14:40:23 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1771972823; cv=pass;
        d=google.com; s=arc-20240605;
        b=kcrcgeuKusm3LhXyLdZXsyX7lqHMmFjw2MKWZrcoJ8HW6PSnQXVhjtZBnhLUm9Kf7V
         8/JW8HYYd7FnQWx8hxshEtTkkOESsBIwR89RbDFZxYR6tPTZpRuEKnmByE2r2An4D0Dt
         VOqYZlaFK8QyuG7ciA8SS1TX1kql105TUouI6ljxSy2FmvRCcQDF9u0UFVsCHAARWItG
         MXhEpjvwmNZr2rR16d38B8GbRVoVsbkFe4XG+t5hAWa31FJclxRyLr/7w3WUM09YOhBG
         jUbzid2Me0QWOOGl4mRUczJARQFjKFymmanGMVtIuLHBJCQGssYGzujrCv5OEk5q5B0x
         3RoQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hUh9Lv4xtoNIyHW53JRACIrki0EBGvCTbDJ/9IDMIbU=;
        fh=cu2/GdG39rPQmxwAxVwHiOYrD4sU3b0PJqHScF0yZ5E=;
        b=FUO3Uvp6KCLP0UkeEW+zFf6laWT5GMuGJoiOiko8OnXzN9x8AANQV3CHJlxlCnleFb
         UgocyQiGTMbQFCIbIv0RR0E1yjDh4qgWs0V0+puYkyJ1jyS4iQ+JWyjGTy+x3rmCRvBt
         xz7QI0d1ucjCsO3sOHaM4lnDUWimH5K0XCXyZ0zBOvupRWdhdprb+CCNyKUD+RIRNFAc
         D/JBzM/MsrzTEeyefjVnjfATBXyHqHiyK0rbc57N5efGjVbYb6Pcu/gA2gXJhYZWa7Bg
         iQhtcaoejQuZGLoZrFj5fADUoLgU3a7/cSOgBqHHckOv5QmyZRCtyQ1Q5cnQDCzOV5AL
         3IHQ==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=UR5CB0Sy;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1229.google.com (mail-dl1-x1229.google.com. [2607:f8b0:4864:20::1229])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-7982de56130si4213667b3.6.2026.02.24.14.40.23
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Feb 2026 14:40:23 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1229 as permitted sender) client-ip=2607:f8b0:4864:20::1229;
Received: by mail-dl1-x1229.google.com with SMTP id a92af1059eb24-12732e6a123so1654519c88.1
        for <kasan-dev@googlegroups.com>; Tue, 24 Feb 2026 14:40:23 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1771972822; cv=none;
        d=google.com; s=arc-20240605;
        b=VQg+aLXUjR2URzSjb3jOkdsFIeDJ+vPxIX69Qoy8kX7+4UIRPQoY2kCkwyhV12ty7C
         Hcuy5MBrPftRUA9vy9hEt9cghAI/gME+eOpZUiIA9ntFZ+KIenOCeaevwDutTAB1YBlM
         r4gcc2eK+AUPGsAH3fa7nolPxy6Ndy6hcRPRzkIlz30loUFSUDNjTDv4vlYezYeDjKCV
         YjOTcsBN8//qAPAF5MNz7iZbf+v9sp1B5y22KPRV+FNbCMCrLdzHNORzbhZOULtd0iGz
         FiVjcGrCPOSRoROxeUeR4poVueH01NF8cIdkDGeC73z5yZlg8t7cHVDqGSJBIcRJwnQH
         HSpw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=hUh9Lv4xtoNIyHW53JRACIrki0EBGvCTbDJ/9IDMIbU=;
        fh=cu2/GdG39rPQmxwAxVwHiOYrD4sU3b0PJqHScF0yZ5E=;
        b=eCo1SOKE7obVPqNoJ3aEZJ2ros20CulDpEF1DaYuz7EkDObLkAusT9DR8incxZnqmN
         mHCpSkSnesubXYz3t7GnK51VgWQ+BIITd3ADjL29xvLE0nC+HvkJE17+AmjnkcniJ5kt
         5J9VqW765Kp2ZO94QfdrsFgfdtZevljMOxpHvq7t3lYlFqt3eK6ZdWk4TdEX83+PKOOf
         wNzGCLdflgqH48gDT7qjGe/2FTR/A5/3FLdcctpWFg5W+WIH4ZV5JIoFFQQ7iLBRdE6l
         g1SQcMuoAYt4+C4/keGEh2t+eWtqhv6YrP7gFy+J5yFgetegjfObe6UfD3ywjsMOQHUC
         SixA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXuaI3hMDCDVl2nzuNXSrDRpvKFw/f+BD83hOeDivhfW8Mg5/1ucxRPzMPr/IUf+ovMVR/txrR2FOA=@googlegroups.com
X-Gm-Gg: ATEYQzyg6sFRMJE303eF9ZDrqqHn6NDNvpLENkiAYWhtk0vmGiYcYBIgnlnhTJRqdaa
	v6CEkzVKO9mhzr7uGdDhPYT4vZZ/3beTfP8T6GUpmBb0RfsDwgI9MQrcnVMN3dChQmZoZL1K9GD
	dDFKErH7foQf2vgMBDGkAxTRLFjAXlkpUtzq3eFrysh6vdh+LepHKIVWwSPK87W8Ss/25a9IHim
	Flyhj0IXMy9epTyXyon4H85WdH2phogmtlwLmlRFcX4yxZpo31XM5puos8SZwFbSBthHVLbxEZb
	kHOoKPnwycT+uH+0hSsRcOuUGZMXkEzJhNr2bg==
X-Received: by 2002:a05:7022:2521:b0:11b:9386:a3c8 with SMTP id
 a92af1059eb24-1276ad8bb87mr6685867c88.41.1771972821528; Tue, 24 Feb 2026
 14:40:21 -0800 (PST)
MIME-Version: 1.0
References: <20260223222226.work.188-kees@kernel.org> <CANpmjNOpXe7tCP7tyR04Hm+a8zdiBWWQdK=US-qTL31mm+Yzkw@mail.gmail.com>
 <202602241316.CFFF256ED6@keescook>
In-Reply-To: <202602241316.CFFF256ED6@keescook>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 24 Feb 2026 23:39:45 +0100
X-Gm-Features: AaiRm52Rk4WC1mpHA3KMq--1fMPzNw3GORR0v5jUwxnBm9gKp2Me32yZwyap6qc
Message-ID: <CANpmjNNZ-U4hT8LaW=V+q+NRPHb=fsxai86CBb1VdV8Pyo_xNA@mail.gmail.com>
Subject: Re: [PATCH] kcsan: test: Adjust "expect" allocation type for kmalloc_obj
To: Kees Cook <kees@kernel.org>
Cc: Nathan Chancellor <nathan@kernel.org>, Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-hardening@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=UR5CB0Sy;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1229 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-2.21 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBV6R7DGAMGQEHWVMM4Q];
	FROM_HAS_DN(0.00)[];
	MIME_TRACE(0.00)[0:+];
	RCVD_COUNT_THREE(0.00)[4];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	RCPT_COUNT_FIVE(0.00)[6];
	HAS_REPLYTO(0.00)[elver@google.com];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim]
X-Rspamd-Queue-Id: E753218D7F6
X-Rspamd-Action: no action

On Tue, 24 Feb 2026 at 22:48, Kees Cook <kees@kernel.org> wrote:
>
> On Tue, Feb 24, 2026 at 11:09:44AM +0100, Marco Elver wrote:
> > On Mon, 23 Feb 2026 at 23:22, Kees Cook <kees@kernel.org> wrote:
> > >
> > > Instead of depending on the implicit case between a pointer to pointers
> > > and pointer to arrays, use the assigned variable type for the allocation
> > > type so they correctly match. Solves the following build error:
> > >
> > > ../kernel/kcsan/kcsan_test.c: In function '__report_matches':
> > > ../kernel/kcsan/kcsan_test.c:171:16: error: assignment to 'char (*)[512]' from incompatible pointer type 'char (*)[3][512]'
> > > [-Wincompatible-pointer-types]
> > >   171 |         expect = kmalloc_obj(observed.lines);
> > >       |                ^
> > >
> > > Tested with:
> > >
> > > $ ./tools/testing/kunit/kunit.py run \
> > >         --kconfig_add CONFIG_DEBUG_KERNEL=y \
> > >         --kconfig_add CONFIG_KCSAN=y \
> > >         --kconfig_add CONFIG_KCSAN_KUNIT_TEST=y \
> > >         --arch=x86_64 --qemu_args '-smp 2' kcsan
> > >
> > > Reported-by: Nathan Chancellor <nathan@kernel.org>
> > > Fixes: 69050f8d6d07 ("treewide: Replace kmalloc with kmalloc_obj for non-scalar types")
> > > Signed-off-by: Kees Cook <kees@kernel.org>
> > > ---
> > > Cc: Marco Elver <elver@google.com>
> > > Cc: Dmitry Vyukov <dvyukov@google.com>
> > > Cc: <kasan-dev@googlegroups.com>
> > > ---
> > >  kernel/kcsan/kcsan_test.c | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> > > index 79e655ea4ca1..056fa859ad9a 100644
> > > --- a/kernel/kcsan/kcsan_test.c
> > > +++ b/kernel/kcsan/kcsan_test.c
> > > @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
> > >         if (!report_available())
> > >                 return false;
> > >
> > > -       expect = kmalloc_obj(observed.lines);
> > > +       expect = kmalloc_obj(*expect);
> >
> > This is wrong. Instead of allocating 3x512 bytes it's now only
> > allocating 512 bytes, so we get OOB below with this change. 'expect'
> > is a pointer to a 3-dimensional array of 512-char arrays (matching
> > observed.lines).
>
> Why did running the kunit test not trip over this? :(
>
> Hmpf, getting arrays allocated without an explicit cast seems to be
> impossible. How about this:
>
>
> diff --git a/kernel/kcsan/kcsan_test.c b/kernel/kcsan/kcsan_test.c
> index 056fa859ad9a..ae758150ccb9 100644
> --- a/kernel/kcsan/kcsan_test.c
> +++ b/kernel/kcsan/kcsan_test.c
> @@ -168,7 +168,7 @@ static bool __report_matches(const struct expect_report *r)
>         if (!report_available())
>                 return false;
>
> -       expect = kmalloc_obj(*expect);
> +       expect = (typeof(expect))kmalloc_obj(observed.lines);

That works - or why not revert it back to normal kmalloc? There's
marginal benefit for kmalloc_obj() in this case, and this really is
just a bunch of char buffers - not a complex object. If there's still
a benefit to be had from kmalloc_obj() here, I'm fine with the typeof
cast.

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNZ-U4hT8LaW%3DV%2Bq%2BNRPHb%3Dfsxai86CBb1VdV8Pyo_xNA%40mail.gmail.com.
