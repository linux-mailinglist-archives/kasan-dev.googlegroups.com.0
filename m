Return-Path: <kasan-dev+bncBAABBYM6SWNQMGQEYXI367I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83b.google.com (mail-qt1-x83b.google.com [IPv6:2607:f8b0:4864:20::83b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6113B619F11
	for <lists+kasan-dev@lfdr.de>; Fri,  4 Nov 2022 18:44:03 +0100 (CET)
Received: by mail-qt1-x83b.google.com with SMTP id cm12-20020a05622a250c00b003a521f66e8esf4199334qtb.17
        for <lists+kasan-dev@lfdr.de>; Fri, 04 Nov 2022 10:44:03 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1667583842; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xy9Znv/0o5C57g75lf+gh+/BXq9ja6OvQ3xymwkRS0kLIj65soutgYoydrLoLrPD3h
         ThuGyXrocDFhUvItJ9fQei82ONSr4fkvY/QNqSHggglxNDZlGcwxsKRza8y1i6msv+KI
         wPKtHhniKvfulXSl0J39jliOsw8LNUdpcbsuhsfUHw0G4DUKXhLNH2Q9A+pCkz+IRmoU
         GO9Gm0gNnXYUQqU9rnRXDaq7akiZdyS5qObvZ3MP/HB/mt3UlnfrcCc+fHrPrCDUZkSU
         LDsoQ16IcsW/L1FsC4ZoX5MHQiMqUyTofU5VLboLGDw4YFAAFifViWz5Uyt8ZCbH2zQP
         8bbw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=y0lPCtxGig8qBPU/9nApqMB5pcoiXAPKWQIcEdRhW/8=;
        b=Fn2KaheFOAAb3XL9ZrqFKcw3fWqjJwU4HPvnJomDwfZaw7xnTXXv81RWd3yU533AYq
         aPSWLYuIc7N3MrmMVM7Ash+6oxcv25gCELj1Lnq2HzBFlvNtXorBx6+LafFfBVxOvI3O
         HWfp1DrbWTm/KIpcen/2MKBSNLt44d4HeLImErfD3MOlDzlW+gu9SWcQI3jx+rWa3BHz
         3oyJVQ4DVedswe+FeFqaaZj+QkWiM8OwIkXAsVO75wrMKDT/IepichT69OobQDCaf5By
         3bCGel0pGAQTo/Cjbmue4ay3oXwMfHIznGstg+lKsEt2OpokwgH8l8srMJ+wyNPDMRdQ
         IJKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j6kZiDxf;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=y0lPCtxGig8qBPU/9nApqMB5pcoiXAPKWQIcEdRhW/8=;
        b=RK02a9Yt+lhXLhZnVDcLc6eyEOmrF+/fT9LpMUun+B4AQkOg3vPsR1IF1kUnnjGSeA
         nynR+cnTOGDzbFOqe60ZkaNG/B7JyrlKicRhfST00JVzV3A6todw7607uAyctZUu/EI+
         4FIHipjJw9lOn//x9hZXaYUQNjOH3WLrFpFQ6vZBP13PRS34WbbPjhQBAuHgg+2YwTAX
         dWiSUAnA+cS5GQWUwLGGHdFkKCDki4vzTgVBW/W5rWH3dcchQISxvGgy0THfjmIdtO87
         UfYxXQt97/H5s8qC5ybSY/QF0pMq1UZAOkq+8Izc3JfriEWdTZgUkkzkCPCtLaitt5OJ
         wfhA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=y0lPCtxGig8qBPU/9nApqMB5pcoiXAPKWQIcEdRhW/8=;
        b=Ko+Vz3UqJBpHJNJD9FL13fkZFDgV6o+ScGxDjhmBMaKT6NNZYMAv4TXVikpMG3V74z
         Xoo6W1S3QaBFIwKIQy9+rcxJlzOMxk6Yle530WOS+6bBB+MSCF2mieR8hr0Zu6XAvw++
         h+S+DBn+GzPS9JqJu8b6Q/t/A8jniYhvxE826byr1OZ3TDDqb25X7Gig7zHX+bChG/v5
         G/Ngk8TbxX9EGA2niRkmqyy1eNcUsj4QJPJuBxAgIiNRuAZFO+qutNaW0LMWzWkwIf71
         ytM0SMHCQb+94f8nc80bmAXYl7wHjEp9ffcJ3lFphGMN5aY59asB54VCjvcA3pNzEFXI
         yA8g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf01CPlBvS3HELALxLeubOr0f93Q/ME6pA6GRHMtL31xxi095TXN
	wTAueS4/Nt82LCDh4J1QjQg=
X-Google-Smtp-Source: AMsMyM4xRdcRXI3rQT/3LPrZ9XUXa3fPQDFingX2NRRuTX1OHIrBgZ1fpCQlyuXLnvtGB4Igv3pgXQ==
X-Received: by 2002:a0c:f04e:0:b0:4bb:61d9:d7b5 with SMTP id b14-20020a0cf04e000000b004bb61d9d7b5mr34124185qvl.10.1667583841965;
        Fri, 04 Nov 2022 10:44:01 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a9ce:0:b0:4af:8fc8:3851 with SMTP id c14-20020a0ca9ce000000b004af8fc83851ls3104311qvb.1.-pod-prod-gmail;
 Fri, 04 Nov 2022 10:44:01 -0700 (PDT)
X-Received: by 2002:a05:6214:2c19:b0:4bb:9feb:9204 with SMTP id lc25-20020a0562142c1900b004bb9feb9204mr329846qvb.74.1667583841422;
        Fri, 04 Nov 2022 10:44:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1667583841; cv=none;
        d=google.com; s=arc-20160816;
        b=xDgFd87b1JuNAsTvnm5bPWjr+7Mq7NR1L6KT8mF2tdiU1ttI3soSEZYXLBiMZBLPaI
         CpL16RnWsr44ZSk4vK0w9yadBRWEM9x0rXuy7fQF6kjaOw03yqKRQleuAvr1L0ZhivNb
         7lIGepw9bzcHRKBoFC7wYyq6BvtxLEMUGKKBqpjmWb+AAh0No5xXm1GEevzvAYAFQ86U
         KgsUnxShDh00F6uunDwgnLIOroH05Sh5DyrRLtRWEtoEf37NMJgG6kANT7L4GATeZyti
         EL7htFhkA3c9jjbtBvTf6nYs4MosOFrMtC/UdZP3BJNCmnkjW61UNtkY+qHcJQgKAhrU
         rIRA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=LymMwm6I7U5WNTpDPXr9BuCrs9jMqTtRWO6ZmNqaMIc=;
        b=mnugZVK32k6GjUVkiP+hohJq8Us/gE2Bq88mKhNa0GoUMDoeNk7fGOQfuFiwKtHzZQ
         GXk3NgHpGsCknP1kBojaXX5IWFYPXKtvNVMjFScCLF2salqIra8khJT6o8HO5Nwvgce/
         v9IhbPKV5gjzWa045CAto/iJhmwVoM5C5iTLnpHq0iBfAG2i8aROpNO8+j3bX50DCJ1y
         +fQTalATfuXxTfMZ9CWD+7tLSSmaOIC7VYklZOOuOusAuoK6Q10eBRPwlw3OegQKFFsz
         pKmd66dHwEP5a5DXI21kM+BPDjP0Ozmg6WrgNIFgYtkCE0aWQqti+ibUcZ8xjv1zyV57
         0qAw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=j6kZiDxf;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [2604:1380:40e1:4800::1])
        by gmr-mx.google.com with ESMTPS id a4-20020a05620a102400b006fa4d3828a3si186780qkk.2.2022.11.04.10.44.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 04 Nov 2022 10:44:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:40e1:4800::1 as permitted sender) client-ip=2604:1380:40e1:4800::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by sin.source.kernel.org (Postfix) with ESMTPS id CDB60CE2B1B
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:43:58 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 28E4CC433D6
	for <kasan-dev@googlegroups.com>; Fri,  4 Nov 2022 17:43:57 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0F1A7C433E6; Fri,  4 Nov 2022 17:43:57 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 216661] fail-nth: support multiple failures
Date: Fri, 04 Nov 2022 17:43:56 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-216661-199747-iRX3pigsm1@https.bugzilla.kernel.org/>
In-Reply-To: <bug-216661-199747@https.bugzilla.kernel.org/>
References: <bug-216661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=j6kZiDxf;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:40e1:4800::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=216661

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
A reasonable compromise between generality and simplicity may be support a
fixed number of ranges (say, 4) and convert all single failures into a range (N
is converted to N-N).

Namely task_struct will have 4 ranges encoded as pairs and, for example, "3,
7-11, 15" will be encoded as:
[{3-3}, {7-11}, {15-15}, {0,0}]

It does not require memory allocations and checking such data structure for a
match is simple and fast.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-216661-199747-iRX3pigsm1%40https.bugzilla.kernel.org/.
