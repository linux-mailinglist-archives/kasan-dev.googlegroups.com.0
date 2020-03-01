Return-Path: <kasan-dev+bncBDQ27FVWWUFRBD736DZAKGQEWGJW3AY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3d.google.com (mail-io1-xd3d.google.com [IPv6:2607:f8b0:4864:20::d3d])
	by mail.lfdr.de (Postfix) with ESMTPS id 81AB41750AB
	for <lists+kasan-dev@lfdr.de>; Sun,  1 Mar 2020 23:56:16 +0100 (CET)
Received: by mail-io1-xd3d.google.com with SMTP id c7sf6961212ioq.18
        for <lists+kasan-dev@lfdr.de>; Sun, 01 Mar 2020 14:56:16 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583103375; cv=pass;
        d=google.com; s=arc-20160816;
        b=CIfe8du6122+cFBvbeL8my7RpPsHI1d+IoQyUyFGezgpWITxqYTesm42nhJYD1zt30
         2/UUGci+Bk0l0HQ15ATyvqEMvFyBgmU+K1hlFllbhyEgllNAIrBww4+DOZGlb1Z2FCKG
         yGgS8lW4fc5qNLentQNAdw+sW5A6znRoM5MKKJDbyosGeAxNei+gnuSrMIuuUceYrt7Z
         5T6IOu4OqTMPRJae175npQS+jblLhl+o1kFoecpb1xSClxrFEHhZwwHybS2AHkPsMb/p
         hBijsirtYliue6EpjeJy0eGjeNFC/ECPYDbPug1jKjfu02hrYKPqJvU2nSec9PO/HvRU
         dZ8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :references:in-reply-to:subject:to:from:sender:dkim-signature;
        bh=6ugQxtQqgcW0xRynwD0i2L9lffPPpuT++8v/UddntDg=;
        b=PhRjn1Xm2uHLc5/JE9fyH1vVyIzQydlYg971bnfej4/OMdGGsc+Zw4hjZYQk12yLsA
         +XxIRxzgPdnhuYCqkrPODO/xfwwGT5oobxYt5VZNcbUiM2d8O7YH2knFgr5JBg+eSiQp
         Ep/pj0MrYCvQd156Kv4Dw8byi+Yy/o96wkrijVHPi/FeYhVLi9ZmilZlXCZ4FhSmhLy6
         HFMNNst5Izlh4edWUaJNznMvd2Yz7+sk6YsEJ4N3P7xG9sp5pwxE8iPR4IcLy2Yrwfym
         hEQGmyy+Uzh3JEAG8f4M8tfYbfBDsYPENxd40JkqjQcguDPRyhYd4OaRed/7ILDVzWy5
         VNjw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=G5lSflCj;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:in-reply-to:references:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ugQxtQqgcW0xRynwD0i2L9lffPPpuT++8v/UddntDg=;
        b=q+iGnR6CPaJfnMZgbJtzCRH37tGYzPr9+ziS5ZooY6KpBTgcQUAttSu8PcyE1efZDT
         /UK3uLpjb7nN0hVPNIX0z2NtJGQZTjduArj+kTEETFNMRfPfHgO5qj9Ndu8WL3ARNyxm
         vsYL/AvMIQHHVG88lvLTCXpgqlF5FcwYC1O18FbobhrIDOu9ikpDQgae3+Jmlpe6d0U1
         hRM0pS6gqwsEthJbtDs5aU1+IVFRH2eb5LgCeH2+WFb7Y0ruImvur3n7sr6llm809H9i
         DMgghYr6uejyr8Eb2NwuCnffs5OatADEkupI5lbYJ9f2g37qZyhV0oL4uEnTAvq8818j
         Wv3A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:in-reply-to:references
         :date:message-id:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=6ugQxtQqgcW0xRynwD0i2L9lffPPpuT++8v/UddntDg=;
        b=Iq3PvtYvCfdwA1qi8ECeZG5JqQGT9Ohc26EFJ2J46WM9d1OScAtAY2LN/yGKb56u8H
         Fc17wv0+2Qw8lTTWMKfqqCDbshIXW34gbMggzTxW5mest3ffGqNf8CxQD/p9ouKvtvKi
         8PXKry2NrLxoWe87I+AhftQvw4Hlvo9TTXjPGxjEjzhpJMDPfvUNkSnjqOMp+DlUGsmJ
         pFxXy/UIL68Mgvx4ebSZH2bYMnjxluSWU5mLpHUEwPNhiXbmuDoEg8nNndJVKFH8t2/8
         StK1bgQkUl9Vtv6Fmw00AoOGKeMnBkN9UbGiq2jE+pS2mpEEHOV68aFFxAktHosREdxr
         1k2Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAXliSBSsdS09HC+iTDPwsZywSdYSVJJyoKAki9Y2D1OmY+ySB8Y
	gb++4UtfI6EuMatN1YrHOMs=
X-Google-Smtp-Source: APXvYqyEbZfoWz9RQSv4B+xD2n8v5gNV2xUkymKL/KOkWC31mLFZF4r5KxCZi0nS0bU0TgQl6MrUGA==
X-Received: by 2002:a92:4448:: with SMTP id a8mr14430695ilm.256.1583103375331;
        Sun, 01 Mar 2020 14:56:15 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:ca92:: with SMTP id t18ls1308059ilo.5.gmail; Sun, 01 Mar
 2020 14:56:14 -0800 (PST)
X-Received: by 2002:a92:d691:: with SMTP id p17mr5945606iln.273.1583103374804;
        Sun, 01 Mar 2020 14:56:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583103374; cv=none;
        d=google.com; s=arc-20160816;
        b=lFf6cOf5oPXOiEfABQSLbFX4piNB3eBi9uRExoiQwmn7DDSHYIIj1NalfItM8zdLt2
         JlUlKu3hRucN0GfKIDliCB5/05AV8JvPAIgoj5QGbebCCeEUZtKU76p7lwNzUv4OAYBw
         5NQlyHY1l8jQSlh6pvTQWaeICStbDIwL81xPHQLaDn18LvJazHfqV9HjJBqxg5JBWdcY
         xI09hD6Wa7dYZinL91qL8ktYjMQPdOn8/in00V+lAnI6ReWZsyJpvfEeRvADbZhUoEi2
         2POEaz9gDSFozGqzny1DPI09ZXSkPEg7qU1nLkg0YW6kDkLvG3SlNhTzMz4jJcE5ZDjv
         UCGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:message-id:date:references:in-reply-to:subject:to:from
         :dkim-signature;
        bh=YxgOqpgbQcmMoGMYAVFOXMchSBvpYzdR5unDu3ePoFE=;
        b=BJ14+WLcdXU+V6QqPTUjMoPNXoZsbLoEhty74+CtPpX/fSxeDn9Tinlx3txjYc55cx
         HT5bfCy6Fqz1927y38fpOzCB7CW7oIx4rYAAFNo0zRgRkhXEG6aBHwWEUYBd4049+Q1E
         rzJtyfWBI5BiPkzqY5gvDS5dfwoawI2iXfkxPTy4i6l10GJGWPx+ZIigp7Do7sit29/S
         9HbQi1MStpnbpUWSywkOFWeO2mzJJ8uzPQfDNRSAwo0Bq4yKFZ5BgAWpAv5dYy6oO0D7
         xxDEViF4aocY9fX67d411uDbbA/+STI/ZFLKdYOQC/OYpImqjzvT3ABq9G407zpaRUBZ
         ldcw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@axtens.net header.s=google header.b=G5lSflCj;
       spf=pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) smtp.mailfrom=dja@axtens.net
Received: from mail-pl1-x641.google.com (mail-pl1-x641.google.com. [2607:f8b0:4864:20::641])
        by gmr-mx.google.com with ESMTPS id t10si93318ilf.3.2020.03.01.14.56.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sun, 01 Mar 2020 14:56:14 -0800 (PST)
Received-SPF: pass (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as permitted sender) client-ip=2607:f8b0:4864:20::641;
Received: by mail-pl1-x641.google.com with SMTP id y1so3421289plp.7
        for <kasan-dev@googlegroups.com>; Sun, 01 Mar 2020 14:56:14 -0800 (PST)
X-Received: by 2002:a17:90a:928c:: with SMTP id n12mr18452305pjo.45.1583103374143;
        Sun, 01 Mar 2020 14:56:14 -0800 (PST)
Received: from localhost (2001-44b8-1113-6700-591b-db3f-06cb-776f.static.ipv6.internode.on.net. [2001:44b8:1113:6700:591b:db3f:6cb:776f])
        by smtp.gmail.com with ESMTPSA id h7sm19357775pfq.36.2020.03.01.14.56.12
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 01 Mar 2020 14:56:13 -0800 (PST)
From: Daniel Axtens <dja@axtens.net>
To: syzbot <syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com>, allison.henderson@oracle.com, bfoster@redhat.com, darrick.wong@oracle.com, dchinner@redhat.com, dvyukov@google.com, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-xfs@vger.kernel.org, sandeen@redhat.com, syzkaller-bugs@googlegroups.com
Subject: Re: BUG: unable to handle kernel paging request in xfs_sb_read_verify
In-Reply-To: <00000000000074eed3059f9e3d0a@google.com>
References: <00000000000074eed3059f9e3d0a@google.com>
Date: Mon, 02 Mar 2020 09:56:10 +1100
Message-ID: <87eeubr8fp.fsf@dja-thinkpad.axtens.net>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dja@axtens.net
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@axtens.net header.s=google header.b=G5lSflCj;       spf=pass
 (google.com: domain of dja@axtens.net designates 2607:f8b0:4864:20::641 as
 permitted sender) smtp.mailfrom=dja@axtens.net
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

syzbot <syzbot+6be2cbddaad2e32b47a0@syzkaller.appspotmail.com> writes:

#syz fix: kasan: fix crashes on access to memory mapped by vm_map_ram()

> This bug is marked as fixed by commit:
> kasan: support vmalloc backing of vm_map_ram()
> But I can't find it in any tested tree for more than 90 days.
> Is it a correct commit? Please update it by replying:
> #syz fix: exact-commit-title
> Until then the bug is still considered open and
> new crashes with the same signature are ignored.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87eeubr8fp.fsf%40dja-thinkpad.axtens.net.
