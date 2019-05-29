Return-Path: <kasan-dev+bncBC24VNFHTMIBB3GZXHTQKGQEUFRTCZA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc3b.google.com (mail-yw1-xc3b.google.com [IPv6:2607:f8b0:4864:20::c3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 00ACD2DBDA
	for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 13:28:46 +0200 (CEST)
Received: by mail-yw1-xc3b.google.com with SMTP id x3sf1792680ywd.17
        for <lists+kasan-dev@lfdr.de>; Wed, 29 May 2019 04:28:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1559129325; cv=pass;
        d=google.com; s=arc-20160816;
        b=qeIztIbtmZMbX9to5vgfWT8WTWQ3xHig7qV6yuoGBctXSjOlPsbyl31A+jZthI2/Kq
         veqtOmgAi8BcSefPAmBAAfOLzzK1nyWZOdH+x5tBEidxwK7pfcDXrbZnZU7YI93O2+Mi
         Li2MLHZblp2Uabv0mKtKmCNTJGTXaMeAUOTqtzs+YKaXyHc25nRTwBxAs4NQGfdmmdtM
         jRU8uqWugLfcJXcnKEv/OIQMjeojE86Y82IcA3w+KyTdt+uzwDWsYGOe7cz3kNUFTXwo
         7l3cFd76XxoqtCA7J6j+Ma+1VjCp/nJMzD4tCkfiWQfGmPQ3dgVj8pB9v7qSiWaZJVPt
         2org==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :content-transfer-encoding:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=H9KH3E98W2mpOc12TnGTeso3KxUznpvUHN/USCUBRso=;
        b=hftI8ZBvMy3tFaI7qde4DXrsCuMPLiVlOsQQvPVi7oo6F0uF71LKDo8bjnGN9zAO22
         OZc5le6eWLkdsDHX5udmU573UAWgT5qJ6s/kM3zbS0sS/hukAqc5VrDHtchY6WQHGSUq
         Nax0FJ/BRUxdt0ZNPPndKI9V7uAJlwSmuIEWhswoua2AixOOlP0r74V/eAvNFWr7d69D
         +bRDAgaq2CiHi9sAQg731m7zUWjN3vFYmNsETkxdOCEgx7eVPO+yc71xGk/3EGOTk5Bu
         71mVFzZ4+CHDyNSHFDN95lgdJNk3DvaGECY1m0Hh0RcVbk/BgaKhneG4d7MjKdL+7I0n
         KZtw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:content-transfer-encoding
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=H9KH3E98W2mpOc12TnGTeso3KxUznpvUHN/USCUBRso=;
        b=gtKe96ggoHSVCqo5pQ5KYEr4G2OtofMsDLEj01MaWMUk2H8TO9M64/ZTkrwOFaSyAW
         1Iw1NcfqzMxLBI9Ne9B+9IV11L2XjyfUq5p65xTzNxa7CN7LfuSWAEK9uux5mt59Ymwo
         VmB7wUiLiKfcUAmR6NhqxuWuOkCLuE51DhImdzmm6xfcCFwyLanbfrCLB52abC4XZaEg
         mUK1wZiWdKga6p996xD4ddkJfdNvKCiiFb0of5GZTvTIkQoWTfT8hC3elduJYUzD1J56
         viD6J59AyzS6JTyuxTpibBE8qODGBNrP09OhMAIesF57ZvfU1XnlGW4FJYwr2jvjK8sm
         4Khg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :content-transfer-encoding:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=H9KH3E98W2mpOc12TnGTeso3KxUznpvUHN/USCUBRso=;
        b=maR45AN8qB0rdjlu4IteaJB4tsbDEY5ZCw4RHzZ1GnXJNznl80qAAuCeIy99fwMCD/
         8NcSZgwSuOY0J168C2rKIctk1A7f32B+liOzD6QReUsdcgjEqt6dxNvHmrK/dDZD2qRs
         ejmyB2aIrMOqm05ndLCf5els+Ovc2QaNTCDtTl7/uRm9g04k+Yx9ABaLD7MhsEejl6Ui
         ugu76BuqsVqb1QUZYrm1XZv5UILhAvMKue41Gxr2owTCEdml0IXXn4yo+9WE7EoBLS8i
         Jy9A7lMwboorkRsLUFDls64jOPLetSKnMRO1Z5VVSQVHRuUbcNb84M1p/zIn7dFCogZT
         LVmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUEh2O6MN9mPZRs/4ksPXq0U6/AOHbpWIh39ZDR83yfdHNclf7d
	ztnCs2E0DWdhQD7gwOIYMw0=
X-Google-Smtp-Source: APXvYqzyLb04xZKV44RNgKB9J4gbwHuuWJYzJdI6WcU0LSFnrN24x8YzpWdUpSW7jgRhsXjJ34Ntlg==
X-Received: by 2002:a81:3758:: with SMTP id e85mr60190805ywa.393.1559129325065;
        Wed, 29 May 2019 04:28:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:25d4:: with SMTP id l203ls186787ybl.13.gmail; Wed, 29
 May 2019 04:28:44 -0700 (PDT)
X-Received: by 2002:a25:bcf:: with SMTP id 198mr14782608ybl.34.1559129324782;
        Wed, 29 May 2019 04:28:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1559129324; cv=none;
        d=google.com; s=arc-20160816;
        b=AuYkZvhA+LKc5zlD/KH4fKVTz4TrZ5lKtwSn8Xy0prLhm5RXH71bbExvKZlgFsblGm
         sIKEBI2BVi8TeQUpwlp8RbUtUQHPGaIo0OCyZYcBHzG8U0rCogbVgvApDtokeaue3TIU
         v6IOgsfZTqkrCq5FGzgwK6Hab3i0ywC2NUdG0JmoAP1gcYDmCYNlhQWXXFl4fQgBafvR
         u/uJ+QnSRs0Dtol6CmspH+JSaEmacLl4L6/NXwMt8MolGc4hH0io/O4tD1RdR95xQAFz
         tBnWBIeNsNFbq/muhm5b700/vl0tajD2/PJ0Vrwjf1M0HdC4yKLBi0zFaG+BWu9gFxUu
         wpbg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:message-id
         :date:subject:to:from;
        bh=Zo1wZ+wa17KCqVKriSz1QH+uzBet8rwj2br4cuACQrk=;
        b=iIDxGKf57SDtBDYNa6Ze5Fhg2Y9rVrMKTt6FkaQYOMFAVg9K+Fvw6Ucu4CxJlveG3A
         Biphu2Q0JxLwx5F/EIiAlAaYe03vN8R0H+ovulnB+KWXLTjC1btKa5Nmel5WUtRZ6SM3
         lsl9PfIPcpCzEKMa7QELuFYC0kS9VWvJUQ2JErV89lcrS8QpwmTgDkO8zEHlunr0Y2A6
         hFnQFY3aqMN18aCA6IIQPPxi9cHeUCOhfMpxqiSTTFNBKNQCRTz+nIchjk4AvbdeXEog
         Rt74iFFN0rDxAARix520TPkanITPSQcwmblxhkm1Pz96jCv3Spe/NbdrX1/9V7Wf+jbR
         TBiA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id e21si851800ybh.4.2019.05.29.04.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 29 May 2019 04:28:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id B4A4D286A2
	for <kasan-dev@googlegroups.com>; Wed, 29 May 2019 11:28:43 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id A961D286E0; Wed, 29 May 2019 11:28:43 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=ham version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 203751] New: check alignment of atomicops/bitops
Date: Wed, 29 May 2019 11:28:43 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: new
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_id short_desc product version
 cf_kernel_version rep_platform op_sys cf_tree bug_status bug_severity
 priority component assigned_to reporter cc cf_regression
Message-ID: <bug-203751-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Virus-Scanned: ClamAV using ClamSMTP
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=3D203751

            Bug ID: 203751
           Summary: check alignment of atomicops/bitops
           Product: Memory Management
           Version: 2.5
    Kernel Version: ALL
          Hardware: All
                OS: Linux
              Tree: Mainline
            Status: NEW
          Severity: enhancement
          Priority: P1
         Component: Sanitizers
          Assignee: mm_sanitizers@kernel-bugs.kernel.org
          Reporter: dvyukov@google.com
                CC: kasan-dev@googlegroups.com
        Regression: No

This come up during review of bitops instrumentation:
https://groups.google.com/d/msg/kasan-dev/g8BcLLjpgoA/qxaxdveBBQAJ

It would be useful to check that addresses passed to atomicops/bitops are
properly aligned, because the future hardware may trap on unaligned accesse=
s,
there is significant performance penalty for accesses splitting cache lines=
 and
it may cause problems with bit/little-endiness.

Bitops should be aligned to long:
https://groups.google.com/d/msg/kasan-dev/g8BcLLjpgoA/Fr5uTbiEBQAJ
Documentation/core-api/atomic_ops.rst
=C2=A0 =C2=A0 =C2=A0 =C2=A0 Native atomic bit operations are defined to ope=
rate on objects aligned
=C2=A0 =C2=A0 =C2=A0 =C2=A0 to the size of an "unsigned long" C data type, =
and are least of that
=C2=A0 =C2=A0 =C2=A0 =C2=A0 size.=C2=A0 The endianness of the bits within e=
ach "unsigned long" are the
=C2=A0 =C2=A0 =C2=A0 =C2=A0 native endianness of the cpu.

This should be done as a separate config (not KASAN) as not related to
KASAN per se. But the existing {atomicops,bitops}-instrumented.h hooks prov=
ide
handy foundation for such checks.

--=20
You are receiving this mail because:
You are on the CC list for the bug.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To post to this group, send email to kasan-dev@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/bug-203751-199747%40https.bugzilla.kernel.org/.
For more options, visit https://groups.google.com/d/optout.
