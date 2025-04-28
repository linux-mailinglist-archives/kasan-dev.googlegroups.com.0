Return-Path: <kasan-dev+bncBAABBD7DXTAAMGQEHI7AMGQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3a.google.com (mail-qv1-xf3a.google.com [IPv6:2607:f8b0:4864:20::f3a])
	by mail.lfdr.de (Postfix) with ESMTPS id 272F5A9E9BD
	for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 09:43:13 +0200 (CEST)
Received: by mail-qv1-xf3a.google.com with SMTP id 6a1803df08f44-6f2c9e1f207sf74272446d6.1
        for <lists+kasan-dev@lfdr.de>; Mon, 28 Apr 2025 00:43:13 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1745826192; cv=pass;
        d=google.com; s=arc-20240605;
        b=iSDvD1u3QsDEKyijB0np64W8VxjK6o1+81E/P2Q5oW5pRm8TBkKfPzRhu/BgxNZ6da
         vOpq8cjDHrtvxg4jP2lMW5zSJ/SsRixwcOERk4KccGMKMX4KIoZvBQOR/aGoggEpDLcb
         OaM8Oht7rWtx2IO2QTVxYOOdnVTb9/0lFWkjKOKWhhDSpZFGjZ0zaeNgZIsd6WWPQBMF
         8eJguiYdXwyBSzkydlNzRcKTBNAJRguZOMUvEepGpUpKA7BM0oer3YjTGIKAFJatNxV4
         aHtcP3kDbIQKN48Qckm2ea8MsfalTSWI/t6DVMMbxK8ldLBXgbGw+NVuafVhno1wb49N
         YfdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=LOLqPP1VLuKJNy0bF/M32jATJiGg36EHjNp7TuMaU98=;
        fh=7FQ3ShjNxPMMHCA5nC2nzW9VYl6jpryj1W0WatNHbhQ=;
        b=KeiYSQgW1iXqI4XWOxan6KgTpHfGreqsP5AOl6WDLfv9rfbV0LNkLvk5v58mOiIXqJ
         N6xg4EKK/JZA5UVSJIoiy0oo76jckQdUwBGtWMYOmC0uK2EtFyT/vXlpIXsr53OR0aoK
         tAoVr+zfDf1hYM7CoTQEtf90VA2YslIvPy9taKEtkPfOq+bZgkVoKgjPD9krr75d04Cy
         bf5YsDnwVgRQzYHi8qAFJuWDM38Aztg8YhiWfXwtn6CoSQen38MQlCI2s7qiMp/u9iBH
         XjrCstXwoQfAPA80gmDEA4aUi0SwO8HxizpJ8w2H8Q2DekE8aaVNegdyUdf4M7NVk/eK
         YDlA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IcktpHWH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1745826192; x=1746430992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=LOLqPP1VLuKJNy0bF/M32jATJiGg36EHjNp7TuMaU98=;
        b=jYkCnWdPPwJGLaye0k7JPM2rqbmA5CGJY2SPW+mMruYlJH6QhPMqOuBxXGEGoKsfoA
         WC/ucLHyUc1/sqjyfXiB5qt0TUcAcRrCOwwZYRwJlTsZBFra6aJujgW4sfXTJwW7O6Ug
         NBIdl9pVlpLauYbylQ/w1Y2R6KJYImd4hPSckvSvYqm3/qpBVk/rV63N3V76r2rEpO1S
         RVNGojYCRC0mrZ4xi+Y2bN9yX8vMjtp59xbLJNCTk0P8OQ7Pwy1jWnv0T8nJiNQriBPC
         cGv0/zv4QTF87GzCgDlfR9uG1+Xjka2GZJK6aL4aa+MhOz0aLRfLOVzm2x/J9K1YkVVY
         O8TA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1745826192; x=1746430992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=LOLqPP1VLuKJNy0bF/M32jATJiGg36EHjNp7TuMaU98=;
        b=goT72fwoR571N+gqRn//BfkRgyWlDlrkRmAPn7PaW3pwo/OeGItM0FgKwQDYHboh/e
         OJe5PXLYWMQ7Tnw9jeBfs2lO8nCriblGSponHbfOCWJ9ZUT3g5G4VpXOI/7Gq7CDK1KG
         qQmly1QJa/Ta84rJGE4u+aqnJ0/7/VGym3toUmBsVYORzd7bGigkSx6zuG+PKfnM1ikI
         Z2Oz6HDOfEhx0SPwcJKtC0nHRJjre5QYFSLFJf/3mY+NpjurjC5gLfVD+rCJZcnWqje7
         Njpwj5CEzmgoEoC8jxpTygDRrqVG2GPLz4VImuWe7yDnv3W0LN02Tr+YN/no0lGv4cjZ
         sBBg==
X-Forwarded-Encrypted: i=2; AJvYcCX/KI+irt2vr7iM7cg2CtBjOnPlGInRE5BImeYm7B0w0CEChjqvL8I2zzEVVMK9XrK7zqgOIg==@lfdr.de
X-Gm-Message-State: AOJu0YyFE5SECRLDSlkd5qWKdF32uR5wBgNK2FqMsLCOCozl3ktIs+75
	JA4sG1gKXJAk//6G20d9nbaqLisrpFD+kbW69Pr+8qFW96q6/M4v
X-Google-Smtp-Source: AGHT+IF6sdzbPi8Hie6R2Ic3vbjcjRDhcMzKudg2dD+ISQIwL/DsdQ8Vsb/o393IFKTrXitGyhctpw==
X-Received: by 2002:a05:6214:19ed:b0:6e8:9525:2ac3 with SMTP id 6a1803df08f44-6f4d1f8f63fmr139172126d6.34.1745826191680;
        Mon, 28 Apr 2025 00:43:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBEXheyjzmggWEUg2bAEUSzfxyiiunSURcZfFXswe3YhsQ==
Received: by 2002:a05:6214:943:b0:6e8:ea1c:4db2 with SMTP id
 6a1803df08f44-6f4be045752ls28178636d6.0.-pod-prod-05-us; Mon, 28 Apr 2025
 00:43:11 -0700 (PDT)
X-Received: by 2002:a05:6214:da9:b0:6e8:8d76:f389 with SMTP id 6a1803df08f44-6f4d1f90d59mr160925186d6.36.1745826190876;
        Mon, 28 Apr 2025 00:43:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1745826190; cv=none;
        d=google.com; s=arc-20240605;
        b=lFzP2tvzTHbj5CI+L1WHOalWAPaU3uloPAvfxf/n4fWGOxIKXZPmZhcAe2BiRKt8aO
         Xf9TpT3Pf97n0J/d0+URtk8tiqa5HGsFCDrruaswxdhmCcnoR40sfmmZfWAUlYQgelJX
         LbnyHH5Rt4hr1dnWVXH4M3x0ygqMhXo9gPY5ENSLfo9q02uvby3P0Wns4Mm6E4X7ewLV
         459NgwUI+LYNQxmJHR4x9mE+sVWsBKR88GR5Ax4TBgZRXysPdcMoaewn9r2PlGbytYrD
         VIlVDEBdkTD4k2Nz7qhUk8G8dDRKRi27v6d5bmrmsB8qI3bF0XDYkbqRuhK90yNNHSeE
         aZjg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=7YF+J7nmVYyo2qixhnbpiI0pXRUK6Uf8D3XYz1v6IUk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=Wo0iRu7HeLq6gYwj9LC9CIs0AjPpSolemg9elWU9VM2JhTKP4/30tc0gq0erJ1JdXP
         ZzgXibQTyjb84WTKUZMXl0cCNOwqqNleVYD+caXcs4wmD9r8tGiAU6Kwx5qlAbmNPTvD
         sJPiar9bK42B4TyR0EyMk9KBJbwUboZrC0TKMk9WleY2svW6y768LBp9WM2qRoLk/FZU
         VY8hunITzxrdEhwCITj/QspWbG09+Xq1s5wGP5+yVXxtcDqESngRfGhpDFj7FPDEahb4
         tgCoblit6P3eXEzF3XJWVy9YO5GNM31ZUEe8WSgZl6gLcDQa4j8VVYZgJawJD9HO32fZ
         te6w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=IcktpHWH;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [2600:3c0a:e001:78e:0:1991:8:25])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6f4c099da77si2249406d6.4.2025.04.28.00.43.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 28 Apr 2025 00:43:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) client-ip=2600:3c0a:e001:78e:0:1991:8:25;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id D4C4D4A40D
	for <kasan-dev@googlegroups.com>; Mon, 28 Apr 2025 07:43:07 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C48B2C4CEEF
	for <kasan-dev@googlegroups.com>; Mon, 28 Apr 2025 07:43:09 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id BCD64C4160E; Mon, 28 Apr 2025 07:43:09 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 199055] KASAN: poison skb linear data tail
Date: Mon, 28 Apr 2025 07:43:09 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: REOPENED
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-199055-199747-HEGqvKW1Ea@https.bugzilla.kernel.org/>
In-Reply-To: <bug-199055-199747@https.bugzilla.kernel.org/>
References: <bug-199055-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=IcktpHWH;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2600:3c0a:e001:78e:0:1991:8:25 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=199055

--- Comment #3 from Dmitry Vyukov (dvyukov@google.com) ---
The recently added CONFIG_FAIL_SKB_REALLOC does part of this. syzkaller should
be able to use it with systematic fault injection facility
(/proc/self/fail-nth).

Does CONFIG_FAIL_SKB_REALLOC cause exact size reallocation? Say, if tries to
get 17 bytes, it should call kmalloc(17) so that KASAN can catch all
out-of-bounds accesses at least when fault injection has happened.

With that extension it may give more-or-less everything we want.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/bug-199055-199747-HEGqvKW1Ea%40https.bugzilla.kernel.org/.
