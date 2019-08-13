Return-Path: <kasan-dev+bncBC24VNFHTMIBBDFWZLVAKGQEUL6CIOA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33e.google.com (mail-ot1-x33e.google.com [IPv6:2607:f8b0:4864:20::33e])
	by mail.lfdr.de (Postfix) with ESMTPS id 3F2D78B668
	for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 13:12:14 +0200 (CEST)
Received: by mail-ot1-x33e.google.com with SMTP id k22sf9630147otn.12
        for <lists+kasan-dev@lfdr.de>; Tue, 13 Aug 2019 04:12:14 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1565694733; cv=pass;
        d=google.com; s=arc-20160816;
        b=GHqOWf2ZnzlR19XaY6ZsMlncJRLc5DGQLVREUIu2MmUPER6DcQH8pxqtl73X2ZLDQP
         3wTP9V6k1aWBzJ7ZjPUUSTnA1D3fVsThXJQvjeqbqYNnM3nv7bRNu93/4KVMuSQDY6iM
         2E93Tyygiywd/kP3fNXkb/lNVZb1UkWefSVXx2dzcDttJ6D1CPYcsipFcDYTNsp6igir
         vcBTIwNBVkKXWaguM9ZInZhRXKPLEOHUV2sZAz4v/isTd7FZkKgTfu1IZcaTlF8x5yKG
         kv/yz/reCy+mHN1fcBmu6FkabcY85BJX5zYTO6YoOq6yWUxe24zBLN/jceRVOIxJ8duC
         5HCQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=QbeyZHpq4hngEf1c9YZPLUHF2kHnEsiu1DS4PEBiLwc=;
        b=VteYorTtWegexcTx6XUXkzRb8dcL5JSChEhyjQFJtaEftWIYIBKvu4OOS4BkoX4kCy
         zLRDgQOhvcvbBCguPn6T4luhWLIIwbtBCQ3nF6qkuVZF91pTPIvbDc32DtLmV7CFCQ/r
         zA4JTk+DSY8mp2AETaW8sUGL4rf88KWziU24magAtiKvDFyAA4KclNdS5Wl+pSQHXYLu
         vBayVnFd5zGpXuorpPQESNmR9Djtn5iWPH8UvHQnrlpgpet2vp+k/+G/wejfvowSgT2K
         h7+jKhFWOpP+QKKJ6l9QSDYPFU0hhQbpe0ITzU6rl3ulG/5czVCu4rZDvqZJCgLK3txW
         K3tA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=QbeyZHpq4hngEf1c9YZPLUHF2kHnEsiu1DS4PEBiLwc=;
        b=XVuJmodAfvrLt7rIYKTxukcHGTe5x68LvI0M180PqELROaHpxZQe1EjN+LxtR/OFik
         XYWtaL1Qm7B0wn40Hi3EGj02hF3VgtG0odgnJyD70+2DbnHlYuUkNPtjaNBjuBf1ItnP
         NU46qz6+HlvA2x/oz27UubwV1eZj1HWmhyhqoI0l/89BcUXBk1nnHyWX+qz5FVi7QH3l
         nyY05Hnk+czS1dDgytVr0HQTW+2zCaqG8OleNlBfQJo+RGKY/4hYrS82cD+qnplXAKYW
         yJDSRGKIbGsynHbytLhurYNEGch8EK1SX8vZOq371aTTlMa7PXlM35AEeXwLjfK5ZWZs
         dSJg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=QbeyZHpq4hngEf1c9YZPLUHF2kHnEsiu1DS4PEBiLwc=;
        b=noNtZ7VQvsekCYhLbyz+MKoODTFN4MbUtsTX+kYmmgBNaPTKci5xwro+tQlGAuF79q
         pVqb9KQgsjrCgika/EJgUpwGouo9+QtvMX1/tFbWN/FpyQWz1G76le9MsZ54Hd/GgD2C
         EPrc+mbeHSRUjx/HmkYhtkVTrBBMbDyK35tXLUzEGt9tidiamHeuGWszb+8tWku05Lyt
         Eo8zsh3riBxC+Ef0jWR5e3w3IFKI5M04+xHZYncjiU7ufTXN7xi6PLEY3/UTG5xcXDtS
         cwqFrskcDYTGqIL0VrNzCF6arfSgr2iz8KXGY2av1sezF18rBBsqRfS7DAlfaG7noFfm
         vLRQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUwuQHL6cfibam13IhF1NKD63fYfmT11zNUGhis0buB88bMN3WJ
	8Sp6bLbKaIobRskdTJtOzrI=
X-Google-Smtp-Source: APXvYqwAnkzKkCkyxK2RNhB3iE0Is3bCe159N0Q/pBOHUUnk0LrjX1SF3Mku5eRt/ROE3Fp4GUTR2g==
X-Received: by 2002:aca:d405:: with SMTP id l5mr1170357oig.46.1565694733088;
        Tue, 13 Aug 2019 04:12:13 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:3f62:: with SMTP id m89ls1784899otc.1.gmail; Tue, 13 Aug
 2019 04:12:12 -0700 (PDT)
X-Received: by 2002:a9d:6c1a:: with SMTP id f26mr2697486otq.83.1565694732532;
        Tue, 13 Aug 2019 04:12:12 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1565694732; cv=none;
        d=google.com; s=arc-20160816;
        b=a/KFB/iy3sNIS2XQD4eLNHGXErAhZ6IWK8By9Uqlp5YnGJcgEsnFv60+eWzo6elW9H
         cwYTxBE1FkgTTHtuwE1ZtZ2sR8jF5RvxFcgqhdbjdoufVM7Cu+9KQk+n2xEUMJhD+IrS
         REazsiZtM2CgkJivsrL+ViVVphwtd/bi6et/w5TLqI39sV1i/AFDPHF0cvnjU9Qn27PK
         CeZYekCzgnIUD+Ro54tbIpBzH/htqMlPPzKvOokA3esm8okHnqhZkraHjyj4+sNEI7kr
         LF0WywS57sS77SKG8pAws9XNPzeTSzTuVAPWLWDz1Y7yWi4j/CQIOZmpox/P/Uc1RoiI
         4k4A==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=Yr4F1wHSIGJlQtlZqBTURLiZh0P64F7+G3gi8BDxABk=;
        b=V5z/3o4fP1MMSvgxxGk5REsvlpNO/CNF5jgPdrfdW4HmWjjChTHN9EyNhicXRLrAyI
         +zviAHd2t6jVuGm/c2eLKUjUIRs1o4tee72zkvxUPQUbJsZ6Ix8aneg1UebEFCmkNVd1
         ORinSyrhrZfq8qdhOHYjs4d/Go+f5ij1yuHEnlWi55814giEug0mlzGHBwOVGzbhcvsi
         QMqEDM0sDvQ0Gv9UbYN8whfTgDmkTZZrBK9KIS1RAFoxd7RyVi9DeivJQLFztHAWmt1E
         I1/1RR2mFR9o+MIlviMAFwWnSmBYfXV3IrSiWD043Or2LVy4cvc4r4xYSdcWOdrpKhGL
         0r+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.wl.linuxfoundation.org (mail.wl.linuxfoundation.org. [198.145.29.98])
        by gmr-mx.google.com with ESMTPS id w3si384430otl.3.2019.08.13.04.12.12
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 13 Aug 2019 04:12:12 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.98 as permitted sender) client-ip=198.145.29.98;
Received: from mail.wl.linuxfoundation.org (localhost [127.0.0.1])
	by mail.wl.linuxfoundation.org (Postfix) with ESMTP id A5DEB28622
	for <kasan-dev@googlegroups.com>; Tue, 13 Aug 2019 11:12:11 +0000 (UTC)
Received: by mail.wl.linuxfoundation.org (Postfix, from userid 486)
	id 8ADAB2862A; Tue, 13 Aug 2019 11:12:11 +0000 (UTC)
X-Spam-Checker-Version: SpamAssassin 3.3.1 (2010-03-16) on
	pdx-wl-mail.web.codeaurora.org
X-Spam-Level: 
X-Spam-Status: No, score=-1.9 required=2.0 tests=BAYES_00,NO_RECEIVED,
	NO_RELAYS autolearn=unavailable version=3.3.1
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 204479] KASAN hit at modprobe zram
Date: Tue, 13 Aug 2019 11:12:10 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Drivers
X-Bugzilla-Component: Flash/Memory Technology Devices
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: erhard_f@mailbox.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dwmw2@infradead.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: attachments.created
Message-ID: <bug-204479-199747-hRkadw0Pd6@https.bugzilla.kernel.org/>
In-Reply-To: <bug-204479-199747@https.bugzilla.kernel.org/>
References: <bug-204479-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
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

https://bugzilla.kernel.org/show_bug.cgi?id=204479

--- Comment #19 from Erhard F. (erhard_f@mailbox.org) ---
Created attachment 284355
  --> https://bugzilla.kernel.org/attachment.cgi?id=284355&action=edit
dmesg (kernel 5.3-rc4 + shadow patch + parallel patch, PowerMac G4 DP)

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-204479-199747-hRkadw0Pd6%40https.bugzilla.kernel.org/.
