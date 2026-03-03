Return-Path: <kasan-dev+bncBC7OBJGL2MHBB67ZTPGQMGQEOMHEPZQ@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id cA0RNf78pmk7bgAAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBB67ZTPGQMGQEOMHEPZQ@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 16:23:42 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-dy1-x1339.google.com (mail-dy1-x1339.google.com [IPv6:2607:f8b0:4864:20::1339])
	by mail.lfdr.de (Postfix) with ESMTPS id 767571F2797
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 16:23:42 +0100 (CET)
Received: by mail-dy1-x1339.google.com with SMTP id 5a478bee46e88-2be191ce356sf1990409eec.1
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 07:23:42 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772551420; cv=pass;
        d=google.com; s=arc-20240605;
        b=IaQIJBfrmlALBJQZ7tY+Imy7zP/HSmIMJZd/bLd6SWMW/o5foJEccLy4md6c8JAI2N
         Z02Y/DFxzQlTeINWNJsh0wqQH/j8iuITXJYkWN+3IYqWuwR87pzjsSo0QOo8SJvfIwmE
         DwAKziuV51DhCoiMX6XNLXcTpQaatWO5ewwWT1CgczQupQrUsJ06IO4z3B2rcF8CM6QJ
         NLRfkmrncQJ/KFLgPTUYluNLvLDztD0VXYRRJE+AyrJPHS+SFL5eMout6ISqr/ygfriq
         oCw3QwEL0l4roxfgPt88IABaCnGHqqTD+53bE1ORsCwwYs9V3es21HpUUidrCmgrQA7D
         /GtQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=2ozSTJVqTXVhEiMJ5fPOhQ5JoaK5c5Ap1jWX/xal3Go=;
        fh=saCcxBa6vjdYUDBIyei6IoA7YehTYlZmPAwF5uuG5sM=;
        b=cLIPJnSvim2/WAcx2zpCgjiC5nHOBioi3bw97/jspx/l4FiTDVol8z9Ocm56S3Jm2K
         6RuWotA9kQCHSUMC7dOV8SaXsS0ntT3FLQhjhMyJHAp/LAL6MBadcwIF90l9MX3ivCt0
         KCwqEhPrKSH9I5LCBUFl61wLqRHYRpE8TMYBDriaMGUjbxuO4++tE5b5vXAH+SzZyr9G
         gcQubgzMT5SRej2FZ8/ym7PvaYCyidwHZxbEaAmqR864GNuDEJVJvh2e23QxG1VJ7W8P
         O4RavwuoFoiiJ/FUD8Nx7tq+MJgI/rpmfs7SoBnk1n9Lkm7kXd5uym3RzCXjqw1G6y4E
         L2xw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HDcfniLL;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772551420; x=1773156220; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2ozSTJVqTXVhEiMJ5fPOhQ5JoaK5c5Ap1jWX/xal3Go=;
        b=u0/pFtrP1Jowy/6dus0+PZOG2VT5FAgkhIqlyafFywKe2h94/bNT6w+ppIvQM56QOQ
         C9VPwhRhWbfd8KrTRGxRLHFOQyT3oBbhGUjrzn/HYQlPzWSZ99X84Ubbq38pCemyOMl3
         tNb+XZSW5+3W7g0mTwjGBgFHt+GtYXr9oIEocIBr5uP5o2ggpaBeQ65cSiwpw8Aww06j
         h6bKHouINSYVY7y6xzkfDVXyp4gp+OxVhNu6A1Q1JEtiVRT9T4zMvLtV0GijFcKR51L1
         mR7nV0DSJC4NzqHQjdSEqVDWj1EPEzTXuwLQckZIR0lGEGqNf0WxB1j/WiUegJFnlRiP
         Bq6g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772551420; x=1773156220;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2ozSTJVqTXVhEiMJ5fPOhQ5JoaK5c5Ap1jWX/xal3Go=;
        b=XFKdhGG9J8iHRwnTSId6Qz6hnqJKq9Dwqv2XaZcaE6Um5MPkZDCOUj+s63h+DqzQ7m
         WuJ97sL4JpS0OpHciDRlczl154dZoo4vCg6HDkEdEKhvwEXYfVjlVNXU7MCavO9sYMfW
         k+woeGokMmmEeAC2nL6rBOZxemdyE60ZUtHCPqhXr356EnblFiUZ8rsz5soVQQuDJMGt
         rbnvbh4/5kn1MDvvyDEZJYxVbiJQiVyWYf6kJn/xii4XyOTg0ul+wcsq1B0qXq7Y+MRM
         u1FhuYTAqjrMkNUXwHgLV6ST/xMGlgKxVRai24NuPZIEA4XT3B0uLeAYqXtFsxpSzEMb
         0Upw==
X-Forwarded-Encrypted: i=3; AJvYcCXnadwgf2y26b1hJXARyl5EcWW2RyB81gAOGxSd+kLnddwaTAX8UQV9OOqiktKyWD/nJ9o1zg==@lfdr.de
X-Gm-Message-State: AOJu0Yxg9ylxXzFU3EDPsKLmTqsyR0fsj7GWnqVhIu0MJ+uzavSUk2cT
	6QON63hl0CgmKNPZHdasaUfONHglNt2zl5xZYocWhsO4iF6HpFXRDAlk
X-Received: by 2002:a05:7022:2485:b0:127:5c54:a124 with SMTP id a92af1059eb24-1278fc40c69mr5825614c88.31.1772551420339;
        Tue, 03 Mar 2026 07:23:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+HiknUEfT+sPkJd7c9336fdSaIm1NoGOXKjKlvK0PQU2g=="
Received: by 2002:a05:7022:ba0:b0:124:a8dc:e519 with SMTP id
 a92af1059eb24-1278256112cls2887370c88.0.-pod-prod-03-us; Tue, 03 Mar 2026
 07:23:39 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCVY89MSvzkwlAiYGhZqY2EobTumMdkAI2fIASb9BXTshdF+tO0oQcfYq5UgaFWLwuG5XAG2A4nlraY=@googlegroups.com
X-Received: by 2002:a05:693c:40d1:b0:2be:6a7:d54e with SMTP id 5a478bee46e88-2be06a7d7a2mr2115053eec.14.1772551418751;
        Tue, 03 Mar 2026 07:23:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772551418; cv=pass;
        d=google.com; s=arc-20240605;
        b=NiNx9P05kSXbAVfhnR4KPSNYmJBNec1LKekLwvWKMOZgsRfc7o3XFA1MRba/azTtQj
         hbn0HyYC2RgZ155MiqQWDubpPmXalHWHhnWyv7ZMPKb8YdpFKLBEgWRFw76o4oRyhz1E
         TizDyuKtiS3hRG1Ql809o97I5T47rDcymgMTK5bESQ6OXacXT2yiqg4hW8cgGcC5RfU/
         J8aQpHexV8pBI+6wC3uG/uzaNh2PTYQklGwkksIJFfuCk02M5eEGgAtB/4x0XYnAnXNM
         4JOicBXSvllTYp4b49KRviZBQyxCso/udVY7jr5D4prmuhAHI1roL/0F8a9v+xrQDEMl
         JLdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PIHHMa2z4DUfmfcEzutr+tGhOCrJS86irFkaV0WK1+Q=;
        fh=+2eJpOfVeNtaszPw6kjFUHBoDyPDr0wI2CQ8em1ym3Y=;
        b=N+Qo4ut7PhMnevfdHUzUlMjzJLMiHdtw5Blkin8RFsMT4l7h1ZHqiHySl3ZU5Lb5ZJ
         jffeUIZt2lG5ZNGvB9IKOElJ424+jE3QksTIB374P+RfddnPFzIs81qNznr3mpWGFAPL
         CXPGGF8t5yB6JkD0Az6GWkKvdibkTa8zEYMhquqrDaqdUuETsnwpFu1QuB+s26GvfPeg
         28KMNGV0nP9AOE7gNeryZ2aBuko2DI1OtEEnbe/rwOipckZ/bE77nNuBOT3kAxHQ3BZA
         LctIulG+4190EsIaDTs6YcEUMQJ3ReWV11w3xeztRekARk4ypaQ3TXbiQHExU/cHcDqn
         BUIA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=HDcfniLL;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1230.google.com (mail-dl1-x1230.google.com. [2607:f8b0:4864:20::1230])
        by gmr-mx.google.com with ESMTPS id 5a478bee46e88-2be1ebe1a9csi118403eec.2.2026.03.03.07.23.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2026 07:23:38 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1230 as permitted sender) client-ip=2607:f8b0:4864:20::1230;
Received: by mail-dl1-x1230.google.com with SMTP id a92af1059eb24-1275750cf9cso4617727c88.0
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2026 07:23:38 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772551418; cv=none;
        d=google.com; s=arc-20240605;
        b=dYp55Fuc3vmC6yM/xMPTKXVHVx/AAgxKScNC09njPY+6OiO7wadDW7lqsh4lXxiR4I
         RROdjBMVGlIf2GMRbP+KyYW+AKYe2uNOFkybNJsozxg/2/Vzrqt0mg4dqBTeo5mIpoS/
         VJDfBl5+Ux+eu2ySuJEQy2y8gMXfLWlooZSMCQJiL7XOiqZQ6FxifGPxjiMWMDgutWQw
         CnNFRERUe/U4hzqVdllzKoca8l+VoVsDTpi7uvx/K+PzNTa6Muwe7g2vmPYozibX1IoE
         8xisym2pQZll1fHRoBUH3mTDKwSMGedDsf9dsHQ55Fyku7pFTF0EeF4s1FMtxWRFzlBD
         yxHg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=PIHHMa2z4DUfmfcEzutr+tGhOCrJS86irFkaV0WK1+Q=;
        fh=+2eJpOfVeNtaszPw6kjFUHBoDyPDr0wI2CQ8em1ym3Y=;
        b=NKFdwoev2vfk1Q7Qqu9xSSJdq1BVoTFE+jAoJDbHIK/mFu5iFGAeEdSZ9TItS7ZRUT
         6EqtHpxBnFPQg7otRsU1XsQB79tcK3+xg8YSYGaDMrF63fV17YtQew4hjLuUvFNhoj8+
         06EC1LITzprDAiHbxy4cFXZa7Q3NlP2el06dgb3cvzSzV7d8X/1/+1FPPow/tWJ15phz
         reds0H4/IDPyE8na/looBTy9s5RwyRhjD8pPH332qlHI2n/MM/P8KwrE6SaJ4eiWqTNd
         VCf84XtwxhorFYYb5te9Bowv/iTPmVSbDO0kXp3OhZ1DX+/O6TvFXsETOEJoHrDOW05L
         RJLA==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCXsPKhiR++c7sfpVmEb7Wri4JWsuKhb+CoVrJG7tHr/mDNZ/qTnvrJJ5QxxiGpdmTbzxUlx+1TiP6I=@googlegroups.com
X-Gm-Gg: ATEYQzyZoYLJdjs1XGyornckqtpJaNm2YxykdBwkN6zYzLC8HNXDnuz+v0VvYUuA93d
	V5LIzUhyQWY2lCAVEosmXvoHVZGPNydMja7bcetAqUHoLyXjuGB+glshKJ/gEBR5c6H7iG5J1CG
	1Qx3vTjdwt6g+BdTabLKjFRC4GLV0E7zqmOIkbZqEngvr5FNf7wE1GexYnARzru+Z5xivvnhslO
	NOHAc8ZLM1rQKX/kAxTkDTrEBwarqBCYdp/sybxB3IaAwHZnTK475+HBY2eBW05EJPNgAsel+nt
	rmyGfvfcNvjHMEo6GRam5cyrJ6raXUSRhbiueG4=
X-Received: by 2002:a05:7022:4581:b0:127:867f:2449 with SMTP id
 a92af1059eb24-1278fb68797mr5039051c88.1.1772551417377; Tue, 03 Mar 2026
 07:23:37 -0800 (PST)
MIME-Version: 1.0
References: <20260225203639.3159463-1-elver@google.com> <CAG_fn=WAwHUpoay2kY6rkEZQGYxoDGVJYf5B59Y80ht7++Lmqw@mail.gmail.com>
In-Reply-To: <CAG_fn=WAwHUpoay2kY6rkEZQGYxoDGVJYf5B59Y80ht7++Lmqw@mail.gmail.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Mar 2026 16:22:59 +0100
X-Gm-Features: AaiRm52TnSdEwOc95PvpVa-fbDTzQ1yxTDERFj9HFe2UexnD_a7PDTE86NyKr14
Message-ID: <CANpmjNNfz9TQcnZWkTXEAzVNdUAAYfBv0-FB-e7oV5PCfsYR5Q@mail.gmail.com>
Subject: Re: [PATCH] kfence: add kfence.fault parameter
To: Alexander Potapenko <glider@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Shuah Khan <skhan@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-mm@kvack.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=HDcfniLL;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1230 as permitted sender) smtp.mailfrom=elver@google.com;
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
X-Rspamd-Queue-Id: 767571F2797
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
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBB67ZTPGQMGQEOMHEPZQ];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[elver@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,mail-dy1-x1339.google.com:rdns,mail-dy1-x1339.google.com:helo]
X-Rspamd-Action: no action

On Tue, 3 Mar 2026 at 12:20, Alexander Potapenko <glider@google.com> wrote:
>
> > @@ -830,7 +835,8 @@ static void kfence_check_all_canary(void)
> >  static int kfence_check_canary_callback(struct notifier_block *nb,
> >                                         unsigned long reason, void *arg)
> >  {
> > -       kfence_check_all_canary();
> > +       if (READ_ONCE(kfence_enabled))
> > +               kfence_check_all_canary();
>
> By the way, should we also check for kfence_enabled when reporting errors?

Not sure, I think it might be redundant - I don't see a way we should
get to the reporting path if KFENCE is disabled. And if there
currently is a way to get there, we should check kfence_enabled before
(such as in this panic notifier now).

> > @@ -1307,12 +1314,14 @@ bool kfence_handle_page_fault(unsigned long addr, bool is_write, struct pt_regs
> >         if (to_report) {
> >                 raw_spin_lock_irqsave(&to_report->lock, flags);
> >                 to_report->unprotected_page = unprotected_page;
> > -               kfence_report_error(addr, is_write, regs, to_report, error_type);
> > +               fault = kfence_report_error(addr, is_write, regs, to_report, error_type);
> >                 raw_spin_unlock_irqrestore(&to_report->lock, flags);
> >         } else {
> >                 /* This may be a UAF or OOB access, but we can't be sure. */
> > -               kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
> > +               fault = kfence_report_error(addr, is_write, regs, NULL, KFENCE_ERROR_INVALID);
> >         }
> >
> > +       kfence_handle_fault(fault);
> > +
> >         return kfence_unprotect(addr); /* Unprotect and let access proceed. */
>
> If kfence_handle_fault() oopses, kfence_unprotect() will never be
> called, is that the desired behavior?

It is - consider multiple kernel threads running into the same OOB or
UAF. We should oops them all, otherwise this change is almost no
benefit.

> >         /* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
> >         if (WARN_ON(type != KFENCE_ERROR_INVALID && !meta))
> > -               return;
> > +               return KFENCE_FAULT_NONE;
>
> We explicitly don't panic here; guess it should be fine...

Yes - it's a KFENCE bug if we get here, the WARN is fine.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNfz9TQcnZWkTXEAzVNdUAAYfBv0-FB-e7oV5PCfsYR5Q%40mail.gmail.com.
