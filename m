Return-Path: <kasan-dev+bncBCCMH5WKTMGRB4MGTTGQMGQEAIADDPA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id qKkWJHQDp2k7bgAAu9opvQ
	(envelope-from <kasan-dev+bncBCCMH5WKTMGRB4MGTTGQMGQEAIADDPA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 16:51:16 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 17DA21F2F36
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 16:51:16 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-35845fcf0f5sf6403661a91.0
        for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 07:51:15 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1772553074; cv=pass;
        d=google.com; s=arc-20240605;
        b=K9NFy2q4ywHKQ/PxnEZOctfX2RMy4K5fMYAWpzRZ+ENpxGNK4Ng3hJ8bF8ZalcK3FI
         MTNkvGDbVMRiF7DU/PFj7dwDC2nroLsyjjqCHDeWZETkflKboTFEa4IHbz7moNolLivI
         IQU9Nrngme+OC8XvEnlh+afrhY7Je6yffdN4rl9z+HrRGBdxSZavD+1iu13KABFTM3yN
         6lqB8cjtElXW0CLVPysUinlUTc7uxkgLL3ODgCtXVV252645jd/DZI8JdO9F3X1TR6r2
         hlTRLO9HiCQuJjSWzk5q308tgtllbKgR52b4r0FrRXYGXkIIhhFeBkaon1zRulUSKlnp
         Gp6w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=zvlEiUz+sgUVf1+Qr79SJdnqi/ZjcoUzEUJ7f+4qEYs=;
        fh=34cPt3XPQSjjmadHdsJzNZqXJXkyTk2oUT5Z0kAQNxY=;
        b=dOWBtKjqEtT1bgnXetod4asdD6EdvW27xSUFhusnwjf7Bklm3uIlK8GfVKGmaJVnv1
         j5WOTgTaKieut4O4oVMxf7p0XVAAWLV7B4p+Tq4ediHfXgjtnE2bD5nuhPcw3N7FvXiS
         7mHsvuTA8qbo6D9QMXpWh4Co/uJVLxnr3QBFfLzFIOJwHlWR/DKWhShH8CpFdOf9jG97
         /lRegsr1x2J6Vev5Tyu/CtCPPqQYl1f44IG8oQc3RU+VPg0Kc5+/ze+lDINYedQ9l4oc
         kowwukPhYiyifbCPNh6Q2CYJkkHy16uEsCro+a3qYdXqR+OhLya8SHkHtR8anp7qtJsl
         uHJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EsHSlORC;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772553074; x=1773157874; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=zvlEiUz+sgUVf1+Qr79SJdnqi/ZjcoUzEUJ7f+4qEYs=;
        b=EqnYgpBloH8VgUYIU8Li6w7pqKqkeTZaRTHhKYIzzU4/ZeY5EinoBlY+Htjqq0tJ16
         zBSeLivRXwpaDze3oHez/Zp0Ta0RNxTLmzBInOxoojjH9G6DOIggocs1vj6xrT1GoWxr
         Wioo96KNbquF3BdBbADIWnZ2efQ7/ZJdDYHOrhowAUEEelJD8rRmOQQrEGsKM5Cn4NAX
         /PTKjuJ4HLIrQ+zrr01+xiGPZuZ2ChU/oSS42TzCMWrfyxVazADjWhyqTKbi4+EObXDr
         jGmqFpNk7gSqvVDD4LkAR8/B4/G4nr482iAAaIaHKDINZL5rNmxMG7ke0wQBKI6V1U1X
         umfw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772553074; x=1773157874;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-gm-gg:x-beenthere
         :x-gm-message-state:from:to:cc:subject:date:message-id:reply-to;
        bh=zvlEiUz+sgUVf1+Qr79SJdnqi/ZjcoUzEUJ7f+4qEYs=;
        b=CasrelfS77irpzPapOZoz0bKbTS3YSnYtKK4J1pRE7Oqba1PID+bEeqCoBjbpEyGAE
         0DqGk5DAauEtDxgseG/7TFpvJ56u6jLG3GhX74f27f3FMos4/cnvuJX90azyVT+YQAmw
         WoPypDAUeGA3KIwHAVGZe0fFN8QZmAOAupR6qHgfj6bf4IsHzW0U8iLUIvNY+HvwJqEv
         Cu8vTKNM0UWR8fDgf48yTijX5KRd+tBX3F7FcJGzTs0gXS7vAIAbaBMzMUdHxIqgjhOn
         HxBxY9i4i7WDoqOqm/xhE0dDr2otIPAiFCKSKm0rcASxnb9UO5FmPJG97d3Wqm7B2Fhh
         3k7A==
X-Forwarded-Encrypted: i=3; AJvYcCUPoXZi28972gMKlY5wL5KydWZVB4lgbK4/sY+HNcnJCLR1iDlm1N3KJeOa7BYjkNx+a9UVlA==@lfdr.de
X-Gm-Message-State: AOJu0YyDgmCAaV+BzBajXdpyOxtBugXvUNntLdL4dhtph7O3/cpzCi71
	a/kV3wiTIWK7kA+UwB3YhLPUVHuvDOUVAk/tGWph1AOWiJnE+xLNC9qd
X-Received: by 2002:a17:90b:2d8c:b0:34a:be93:72ee with SMTP id 98e67ed59e1d1-3599ce3e35amr2609853a91.8.1772553074095;
        Tue, 03 Mar 2026 07:51:14 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+G9mY9hl43y8cREYshyf8vi2HahDrjEuwdzzsugbTVA8Q=="
Received: by 2002:a17:90b:1289:b0:356:6d74:9ceb with SMTP id
 98e67ed59e1d1-3597f82d39als1204547a91.2.-pod-prod-00-us; Tue, 03 Mar 2026
 07:51:12 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWtcYHUkjWelPSFWM1/kqnOO9Q4FxMvZDLg4YC04KPCFpcupkFD9jyP2zegQw7CtttnsEbgfYgz3q4=@googlegroups.com
X-Received: by 2002:a17:90b:2d8c:b0:34a:be93:72ee with SMTP id 98e67ed59e1d1-3599ce3e35amr2609781a91.8.1772553072433;
        Tue, 03 Mar 2026 07:51:12 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772553072; cv=pass;
        d=google.com; s=arc-20240605;
        b=G3xsduBgvcmu1plQ4wF/xdaHVm/NggvZuCAdNEcHstznib9CqFokrGhLyzFnlVBHZM
         gk9lIxHHg9tMgvYn2dm+1L5upQHbUfyKFhV42mJkarXclhWNB12SxGx6dOqk0UqwTZLO
         VnoPidz2fv4m6GMtp7llcmeuDyKAfO6w3A3mGqo01tgIEgpWZptTruQDnI6nec76uw49
         L6DOPt4yVyI+z8svdAe9mpk/+PmK6KweJNWicg2nzSZTO5O/gry4ac5BzjigBncmokgi
         xFpoyMF0yF9qDDm+Ku7qOGjgtChtAxdoHfYtQ+87YP4NmzVT23J1lM5CrbZPZm7BHCGI
         J9CQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XX2std0eOKpVnxlasP7zVX+3pxODM6r50zuPsQkksH0=;
        fh=4Fd/bJDQjr0c3gasvv02YoqJ4Omm/BTwJ9fPcP+tlos=;
        b=YWEkG4xBJ486vrgUO41hkexRbcbNmDZzBPM5moGluJWCh3T9Ak2moFYpOBf9ZihR2F
         0m/VR0lUh9vu4AL6rcgRPM7PeoIG3MkdKfrjB0b7Tho1uOvE9JMsQkrEx02F162uf38K
         k9bUU/2jgCoGfc2HQSbcj5TR3xAuIXA5pJdjJ7BPYiZNyMZ+r72cuQbNPdUx4rDnF7B1
         I48HtQcD2VbAOKDWVSLcSIrYE9NM3Va8rG37s3I9+kTj8bxJslhfxbteK0tgAKDwnUrB
         WVFfz3sGY49vOFgNqP4Iw5fVBn3SOVrOVRfeN/gJCbMMWFB7cI9QK0Q6bvws6442ZbGG
         QwcA==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=EsHSlORC;
       arc=pass (i=1);
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf2c.google.com (mail-qv1-xf2c.google.com. [2607:f8b0:4864:20::f2c])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-3599c08d7a8si70983a91.1.2026.03.03.07.51.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 03 Mar 2026 07:51:12 -0800 (PST)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f2c as permitted sender) client-ip=2607:f8b0:4864:20::f2c;
Received: by mail-qv1-xf2c.google.com with SMTP id 6a1803df08f44-899e85736e2so30647976d6.1
        for <kasan-dev@googlegroups.com>; Tue, 03 Mar 2026 07:51:12 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772553071; cv=none;
        d=google.com; s=arc-20240605;
        b=aOoIQ3RcLluDCxpzqoej17IE6U/QsmVnC0JMTORFqkcgwjD8tn0st8zNuXV2BQYDyp
         3XUR5NLExJRjwQYq1du74aY2+LOkrSBsIYkq7lDmlJRIHQXNrlxPORbXficwcR2nM/WQ
         +S1pPn9ftpCoayrCujavQxT3TTIkjx8MS6pFdglePfli36m1u0cre/aP4A+2xDQLS1bH
         Z4TNmtJoNJyC7nh55MR4haXzrWawyJiqm1mpxOfzoVgdcL8a8oo8l/inIe0VolMBsvaA
         tQJKxdY/1/fujoLUKCEeulv3BroL3RvdL+XDq2y0cf+MVJayvD+dqhfj7lwlzyH/mVDa
         AKrQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=XX2std0eOKpVnxlasP7zVX+3pxODM6r50zuPsQkksH0=;
        fh=4Fd/bJDQjr0c3gasvv02YoqJ4Omm/BTwJ9fPcP+tlos=;
        b=LFhavzJxNZ0e+tublqFJJOsgsIFtJVTc5YMUwSZtCoMjbXySEFfcRpV7cw40ozgKDV
         vPYnFpDk66mcvIKh0lfdR/jERPZPnoWC6Enss9RLhYaEvOCnw4WGKBD7ytdouz6Y1rWz
         XL4/dCcT3OuGFZXqq6SD1+RsfSRyZet/zrE450J7fYEEiN9j6i3Wqi4N3EmPJN4jVuYv
         Fh0dNtcdpR/zC7OboZXFrp64XjmFTTBze0hsjizYFtt5aubY2BgycaeGDTrFPmsLj/GU
         PbAXBtwhtJ79lqD5wstiRVOLRyUG6JPLXrW++7Bx5j0qkRUHS/I7FZv2TrhY1Vs1dC6a
         qI9Q==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCWkdmUkqRcgYurSIwZkmt5JGkwGSnE6BEp9jPWR4q+9QjyD0M0vdY1/tmlzU2NWRShoJSg0tKY+7gw=@googlegroups.com
X-Gm-Gg: ATEYQzxeQhI51/I9r9mGZ7tPKHV2yKpaOA16isjYdr+3yzCpWb42sIFYgTwUQbGhlvv
	+GvpLlgbZvNLgKW8ThenXZCy1nF/EonjypD2QuRSEZbL97LjUVrMk8NRhWSOpISR2kTnIgYB4Dv
	JBF5/UpWn4WxPv0BJo3hGBZp13SMvt6GWtFj/T7k9dnIfKG+GaTXagjavSN8pg1OXoJ0IexCkxQ
	2XlWpM/fYc3hPXG1VABNcDA1Pgt2yLNqp219muz+/S2ucADs0TPVAOvMphuM8RSyE9pHSd8/t7q
	rO7J/Uy/QU7+5TSUdQin9J8dEp6ZMPIrc3yv2w==
X-Received: by 2002:a0c:e083:0:20b0:899:a655:1e1c with SMTP id
 6a1803df08f44-89a0a89f981mr24703846d6.18.1772553070977; Tue, 03 Mar 2026
 07:51:10 -0800 (PST)
MIME-Version: 1.0
References: <20260225203639.3159463-1-elver@google.com> <CAG_fn=WAwHUpoay2kY6rkEZQGYxoDGVJYf5B59Y80ht7++Lmqw@mail.gmail.com>
 <CANpmjNNfz9TQcnZWkTXEAzVNdUAAYfBv0-FB-e7oV5PCfsYR5Q@mail.gmail.com>
In-Reply-To: <CANpmjNNfz9TQcnZWkTXEAzVNdUAAYfBv0-FB-e7oV5PCfsYR5Q@mail.gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 3 Mar 2026 16:50:33 +0100
X-Gm-Features: AaiRm50oFjbSzRbajGzbxbdZNPrSH3B1_BNVoEG05ijQc5OU5p9gEg4qp---aio
Message-ID: <CAG_fn=VczquLYh0zs-Rh51=B=J0k9EUtdoqrKncKy-n5jHxFEg@mail.gmail.com>
Subject: Re: [PATCH] kfence: add kfence.fault parameter
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Jonathan Corbet <corbet@lwn.net>, Shuah Khan <skhan@linuxfoundation.org>, linux-doc@vger.kernel.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	workflows@vger.kernel.org, linux-mm@kvack.org, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Kees Cook <kees@kernel.org>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=EsHSlORC;       arc=pass
 (i=1);       spf=pass (google.com: domain of glider@google.com designates
 2607:f8b0:4864:20::f2c as permitted sender) smtp.mailfrom=glider@google.com;
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
X-Rspamd-Queue-Id: 17DA21F2F36
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
	TAGGED_FROM(0.00)[bncBCCMH5WKTMGRB4MGTTGQMGQEAIADDPA];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[glider@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:dkim,googlegroups.com:email]
X-Rspamd-Action: no action

On Tue, Mar 3, 2026 at 4:23=E2=80=AFPM Marco Elver <elver@google.com> wrote=
:
>
> On Tue, 3 Mar 2026 at 12:20, Alexander Potapenko <glider@google.com> wrot=
e:
> >
> > > @@ -830,7 +835,8 @@ static void kfence_check_all_canary(void)
> > >  static int kfence_check_canary_callback(struct notifier_block *nb,
> > >                                         unsigned long reason, void *a=
rg)
> > >  {
> > > -       kfence_check_all_canary();
> > > +       if (READ_ONCE(kfence_enabled))
> > > +               kfence_check_all_canary();
> >
> > By the way, should we also check for kfence_enabled when reporting erro=
rs?
>
> Not sure, I think it might be redundant - I don't see a way we should
> get to the reporting path if KFENCE is disabled. And if there
> currently is a way to get there, we should check kfence_enabled before
> (such as in this panic notifier now).
>
> > > @@ -1307,12 +1314,14 @@ bool kfence_handle_page_fault(unsigned long a=
ddr, bool is_write, struct pt_regs
> > >         if (to_report) {
> > >                 raw_spin_lock_irqsave(&to_report->lock, flags);
> > >                 to_report->unprotected_page =3D unprotected_page;
> > > -               kfence_report_error(addr, is_write, regs, to_report, =
error_type);
> > > +               fault =3D kfence_report_error(addr, is_write, regs, t=
o_report, error_type);
> > >                 raw_spin_unlock_irqrestore(&to_report->lock, flags);
> > >         } else {
> > >                 /* This may be a UAF or OOB access, but we can't be s=
ure. */
> > > -               kfence_report_error(addr, is_write, regs, NULL, KFENC=
E_ERROR_INVALID);
> > > +               fault =3D kfence_report_error(addr, is_write, regs, N=
ULL, KFENCE_ERROR_INVALID);
> > >         }
> > >
> > > +       kfence_handle_fault(fault);
> > > +
> > >         return kfence_unprotect(addr); /* Unprotect and let access pr=
oceed. */
> >
> > If kfence_handle_fault() oopses, kfence_unprotect() will never be
> > called, is that the desired behavior?
>
> It is - consider multiple kernel threads running into the same OOB or
> UAF. We should oops them all, otherwise this change is almost no
> benefit.
>
> > >         /* Require non-NULL meta, except if KFENCE_ERROR_INVALID. */
> > >         if (WARN_ON(type !=3D KFENCE_ERROR_INVALID && !meta))
> > > -               return;
> > > +               return KFENCE_FAULT_NONE;
> >
> > We explicitly don't panic here; guess it should be fine...
>
> Yes - it's a KFENCE bug if we get here, the WARN is fine.

Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
AG_fn%3DVczquLYh0zs-Rh51%3DB%3DJ0k9EUtdoqrKncKy-n5jHxFEg%40mail.gmail.com.
