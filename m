Return-Path: <kasan-dev+bncBCVL5GMC3MJBBTNP6DYQKGQEOH5WSPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x339.google.com (mail-wm1-x339.google.com [IPv6:2a00:1450:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 678B2154522
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2020 14:42:37 +0100 (CET)
Received: by mail-wm1-x339.google.com with SMTP id b202sf1797wmb.2
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2020 05:42:37 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1580996557; cv=pass;
        d=google.com; s=arc-20160816;
        b=KS2iJSycqPcOS9augSYlBeXOfnXZzUawzn+8ZjSeVzOe6Jm2lKdmBI5/qvTwSIaFp0
         siNLYSsfGYtamHYWpL3W184hP9j0jDnb+l4R2RWm/v1Msh0I1FB8L+PMZh053UVUQpFj
         Mw5Hu9F2Ov1Y/B0WeZhAHqr/HuvH1QmH4z9MBl2xOSJ87YJfiq2LaHPLLSMsl30PTxXZ
         yneFig8Sf/hjJqTdVozGcKxjfzOj1I3y756vNhsQGzDV7B/MfgCkpfiKrJtKvgEr0Zwe
         LmGa5amAAsl4VSqBOEFNRGd2i3WcT6JNlWA2md0Td2+Gko2B7wmYf5Zk2xmfp+huv9EJ
         2adA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=ky5py2Qw6vI9jaMg35GkhnjPLrs2xdLj0KgeW341Mm8=;
        b=J17/eGUonBv/zFKYTicH8/dG8jboSB4QPa6z6ArM/U6hFioFwzncUAH4lNaLZx898U
         OIWPg0y3khjs8IuwHbqy5GvTwXgdIPTEGO+t8LqrxxE/Vb0YH7syP4lWmcI/LnRhhl0r
         DeRHdwct6NNCVFKjHAmIDb3HP3hkEZ8V0ImH97/ScZjcn9TQ63MY1Y9qqrTU0R0O1vNX
         zSXl/NA/gKb5WVMg1I9qacslokR4kJWLmjhmWQ0xxOug51stnRGQNjqPyQn5N4bDDCgI
         PIgntioGSGtjERYd0tSywp4ctto84CQRNuPHhV2lNAaHontHh/sMvANIWekf+UgD+AOD
         i9Pg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YBzYe1Gr;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ky5py2Qw6vI9jaMg35GkhnjPLrs2xdLj0KgeW341Mm8=;
        b=i/rlkXvuoPFpzscwvRdwowQbTDJPb6JTbMCNkwCBJNn9mojKPMuu6txegtVGWhpJFS
         z0yUIvyy2/+Q9/qjBg21QggM+yCOYMocKkJigEPlML8C7oTepu1EFNGaDwzQH2+X9/pD
         iqp9RB9mXA98WWfwV2rJYIc1UG7AUUWC/LcC9sJNWgN097B2+w+no4R2w3ZPqduzgV9s
         Y1BT4uz08qou+Cc+JXAPRd+/JBgkB4GbskSef0zewdrDpj0gpo7Xbz5YTfG1/NusmhFE
         pZPjzdEApTiVc+YwhqVYTm/OBxFE8lTIRZcvyaJzCdyImCrYrXuSJjRSXbAtQAj4VurD
         cD0w==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ky5py2Qw6vI9jaMg35GkhnjPLrs2xdLj0KgeW341Mm8=;
        b=rAK0ywBfRU7dBJXjmeTrFVEHuaXvGbRjsgWNMbgNHtaPCwYBaNbBgM2tNEXEoG2v71
         Bjo/KzYPGsCDEkYlcKkS9JME8xdCtcwnYMBCm7KMl9PStTTFaibp6XNzdH24dXooroRz
         42XVxzg6ZtOAgk1uxQAlyzuuSzqN7CAS1d4skq/8PuCJGJc0VbDFn0yYxgPP2cCoy5e+
         A2ZZhHtEMFajUCadfMyUZORUasaKyPrTEK+tNj2P+grCFojzUDuaB1y5Ca8DGx1UNXoW
         bIYUDXSkQy7xOOvjKA+2ntAHVo1cx5m+D2L121XCKpYtXMakkrHGBUUc/LM3NhPOEL++
         hmNA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=ky5py2Qw6vI9jaMg35GkhnjPLrs2xdLj0KgeW341Mm8=;
        b=CjW+iAvNOdDd7O3TVG/iKnxTcg3tBzW5zsNZ4+HfvLVh+7Z97l9CFp9Ugg2NnmsRJg
         TlBz9lSVlyrFvwjJPnIIsRnkxzzsT1E8Tq1uun0fdSBjlgC4mzJ3sCNpH03rgHSvNT3O
         oqXEpx+H6ilpmzUp+Ti+p7OFDhIJauf5KfwgC9w8BAwTcuXaBxVe1GXDBlSi3d1sN9JE
         UVACLXZVopAI8DBemk7RK8kXLrafdpjECF1D+5fCvSNC3XmgW3IFNXx7rYP+SJJBpDT8
         u4A5ScOpDnHJs8wCf8RobmDDH3P6Kh1Qb33ZMSfmoEMhfbwjJoSI8moNo7Xr/W5/yVV0
         lVXA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVrnPEEVz2AmxBIJkOQ6qdIOjT1oi26oreyDdq+ZewRjgQXCa8I
	04S6T0v8CEC8EZdIXil8K5U=
X-Google-Smtp-Source: APXvYqyhqy7TaSNPoJ3ruh67iedWrCRxy6AWHIKGwvsZDyVzeBqVssJni4C6/MeqFOOjI2Y3oVCwmA==
X-Received: by 2002:a5d:6a0f:: with SMTP id m15mr4117784wru.40.1580996557089;
        Thu, 06 Feb 2020 05:42:37 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a7b:c4d0:: with SMTP id g16ls5183912wmk.2.canary-gmail; Thu,
 06 Feb 2020 05:42:36 -0800 (PST)
X-Received: by 2002:a1c:3b0a:: with SMTP id i10mr4916397wma.177.1580996556381;
        Thu, 06 Feb 2020 05:42:36 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1580996556; cv=none;
        d=google.com; s=arc-20160816;
        b=p2aIzUpPn/8oU8QKd+K166Nn/BRcwJ+iOdaq7jQLDpc0tjzr9HaPQgUV9dfcM4QdhP
         a+UX+zUZ9+qtJGQFS3QUdHWM/ANX9BX5LkSax0w1edxjWyrS1ftF51Sm4RSgAy6N1Rfh
         h7JGHYYSqwkZmn4Cw7pJdUH8xnQuteHn1jnsfViM/9N2h8YrXaFK8Td/BV6wApiSAlmP
         0VYfJtBi88FJAU5oDEqkmDTgZCt4iBTZLcViWCTaPoR1tsQNBJqrw1qoJZVGIW/tIoLD
         n5fmqTQJW0lz2kz2cS3XJy3mIIaFBLdJ+pbfQW6JmNekSaFX/X/ePCX7QpRihPgzldZs
         e5DQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=ksZ9yvJQLEPos9sVNg0k5UIVDrjEW5mJFI3LUcUgjiE=;
        b=Yr0lQ+oinBF2l+5hsVDBVLqd5B1vFQAtZwM8x6Dxxj/KWlqnZHw213ftOj05a/d24g
         eKm1I26jtZt7MZ/MSHLCRolC2uans4xtEgVBoCGxiYpZ4hgU6Hwdv0Q6Q2NboWN00UZ2
         4T4ltVucFE+o/URRzP0/C5oOT68miguzYi+0euv4Gpjo4d9jbZcGx5WfDTsgtRmHRxUe
         97eeU45a+S5x4rQEebIRXKwYVyr55g8zG9N3ty1PaedQtqlp/B74N1iDRV+RzU/mDHkK
         CWN56T60lMHStrS5b1JdQET/uUz5jpJeiZ7zMGp3Nj+T/ouETvUzrKNaxnGQGb62VIFx
         t8Bg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=YBzYe1Gr;
       spf=pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ed1-x543.google.com (mail-ed1-x543.google.com. [2a00:1450:4864:20::543])
        by gmr-mx.google.com with ESMTPS id w11si186175wmk.0.2020.02.06.05.42.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2020 05:42:36 -0800 (PST)
Received-SPF: pass (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::543 as permitted sender) client-ip=2a00:1450:4864:20::543;
Received: by mail-ed1-x543.google.com with SMTP id v28so5935251edw.12
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2020 05:42:36 -0800 (PST)
X-Received: by 2002:a50:9fab:: with SMTP id c40mr2909724edf.15.1580996556072;
 Thu, 06 Feb 2020 05:42:36 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a05:6402:22dc:0:0:0:0 with HTTP; Thu, 6 Feb 2020 05:42:35
 -0800 (PST)
Reply-To: eco.bank1204@gmail.com
From: "MS. MARYANNA B. THOMASON" <eco.bank1204@gmail.com>
Date: Thu, 6 Feb 2020 14:42:35 +0100
Message-ID: <CAOE+jADL2tQtxnss4JDuRxkVKW4JxaCbp0Qs6yS1TUz9=xjM4Q@mail.gmail.com>
Subject: Contact Federal Reserve Bank New York to receive your inheritance
 contract payment (US$12.8M)
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: eco.bank1204@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=YBzYe1Gr;       spf=pass
 (google.com: domain of eco.bank1204@gmail.com designates 2a00:1450:4864:20::543
 as permitted sender) smtp.mailfrom=eco.bank1204@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

Attention Fund Beneficiary,
Contact Federal Reserve Bank New York to receive your inheritance
contract payment  (US$12.8M)
Payment Release Instruction from US department of Homeland Security New York.
Contact Federal Reserve Bank New York to receive your inheritance
contract payment  (US$12.8M) deposited this morning in your favor.
Contact Person, Dr. Jerome H. Powell.
CEO Director, Federal Reserve Bank New York
Email: reservebank.ny93@gmail.com
Telephone- (917) 983-4846)
Note.I have paid the deposit and insurance fee for you,but only money
you are required to send to the bank is $US25.00,your processing funds
transfer fee only to enable them release your funds to you today.
Thank you for your anticipated co-operation.
TREAT AS URGENT.
Mr.Richard Longhair
DIRECTOR OF FUNDS CLEARANCE UNIT

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAOE%2BjADL2tQtxnss4JDuRxkVKW4JxaCbp0Qs6yS1TUz9%3DxjM4Q%40mail.gmail.com.
