Return-Path: <kasan-dev+bncBAABBPUU2KRAMGQEAI5MYLA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73f.google.com (mail-qk1-x73f.google.com [IPv6:2607:f8b0:4864:20::73f])
	by mail.lfdr.de (Postfix) with ESMTPS id C29236F7C07
	for <lists+kasan-dev@lfdr.de>; Fri,  5 May 2023 06:46:55 +0200 (CEST)
Received: by mail-qk1-x73f.google.com with SMTP id af79cd13be357-74dfe945c74sf76944885a.3
        for <lists+kasan-dev@lfdr.de>; Thu, 04 May 2023 21:46:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1683262014; cv=pass;
        d=google.com; s=arc-20160816;
        b=LgCT8K257y51aFSl9QpAAM01guFGrWFhqp1QO99RCzGM+iTt+w3Jrg+iPyUC6fZ8Zw
         iEaIGsphopKDLgSk7xe6GsEk3bxDbyaLvjqH8sr1i5qASVaEaBA0bcCdalNH/qMRWjJy
         WIIVp7IPfpW2kZiGUzXcBGvcUODrJEHsrgCEEBtdG/COhRQF2ut8LDBOr/Doqlg+Lno0
         rfnE2HexkxGOHaihyyo4xFmoCkUrAYX0vJNwepkr5xyToZjBK2QfYH91xfI/RR1zBkNc
         I4NovfGyWvi995GKAevlNavtx9AAfwJuMKANhwpRelWr7XBY4T6YEt3honnePLecOHai
         yBdA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=1msodxuEhgU+aTjXxIeYNbFkXETwASzQUOZmkcevDtc=;
        b=u+48dpbYkZgOrYMuf4noYxGk/wk8tVSDsHB7GPON1bMPIaMuGTjO2er+KkHyyYYBIQ
         x+qzQ/+5QPVyOVTEvFW8UFNTnH8+CF2FpaERLp8oYZ6Kwhl8oGm5xQa84QJ6R2bBtsaD
         Vtf2V9gRZk6lKMyLMm+kyrpef0kEY5QQzjGycZr7bUP0BnLbC+GfBcLqhSUsYVeZFpYR
         wpID08aPBMYq5VhuYiH8XAu7MlYJKVhtQAcIbt55LCku642sFpZoqe2hIBigimverP8C
         X+fNi3vDyT6XpK133WiKVucZ6TcnBxq0i7JMJCQJ8iYGSZUzSaWEHLBPhL1pm5uuT6j5
         arrg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TKQpJU5b;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1683262014; x=1685854014;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=1msodxuEhgU+aTjXxIeYNbFkXETwASzQUOZmkcevDtc=;
        b=MxqkjMiEt53evVL4ZAecOShVXzaUs6bxTT/GkA0GGw2TAF7oPXkLxR5Tde60BMt66L
         YTjFyLPoU1fP8Om0rTy4kse/JHHnBUFHVvkQSWufpSEuUh1otRq4+68sevPobS97zY/k
         yRKTrCLQ4pkEMiATZlo8J5m6q8uZdH9AEZRESaEfLWHESkG1kXIUJm3llKSDMKr6CSwu
         PCY462bhC8bj31+cV/0MuSyZ07z0AXsy0ejWhRdAG0lPz1EY2w5Fvpkaso+rqh2Bmkgr
         MwGNY3jxFLUtL9luOEosizV0ATnxLCBdrOLxjBkBueUJWHVMdo7fbRRPDV+vz6BqkfY5
         mNVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1683262014; x=1685854014;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=1msodxuEhgU+aTjXxIeYNbFkXETwASzQUOZmkcevDtc=;
        b=FgeH41Qo3QqvYWO3yDn0vrQAh42aEvAxWWk395mtHa1vxr/0Ed/ARBnacGcgUFlCEF
         etLAQB9mfUaV/SnfVPSR1fOYAwMHghh2QsAlfVczz8Fj9lu6e6dqLghgjjkM7FgMcbx6
         dRXuecygif77InLGsaIZrxBqGlgpKljk60CJD5XP3mVGtUT3FGwxwbuug5GKmbkxzw0O
         mECVbUW4o+1MGDMw67Bb9VqOSf5/x90W5E3tMuQhZJYefa2IS2vLGK+Cg7nu35ckEOWR
         X8Vhq2X3H9uXWhADuxcYHteQoHo7GA0LGCSc//rJ5Y5elUj4PCMl1HdvYZ3AT2dtGTIx
         rNCg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AC+VfDyK5nzRHpAPwzjYGD42OTwvrr0gJu6Q92CLVUHk+/+FSgWEJ3ER
	8E3xXJKZI4TYUTh8GVCnuzk=
X-Google-Smtp-Source: ACHHUZ7lPUKpXEx/a6EIR0oj6OTzMPcBG/g5kDxtNps8Q7yAdCiwekmxYKVfykve+UYvnuJWdMkw8A==
X-Received: by 2002:a05:620a:3715:b0:74e:8b1:37f6 with SMTP id de21-20020a05620a371500b0074e08b137f6mr22563qkb.10.1683262014505;
        Thu, 04 May 2023 21:46:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:622a:1c0d:b0:3ed:b79c:22b0 with SMTP id
 bq13-20020a05622a1c0d00b003edb79c22b0ls19245697qtb.1.-pod-prod-gmail; Thu, 04
 May 2023 21:46:54 -0700 (PDT)
X-Received: by 2002:ac8:5747:0:b0:3d2:a927:21bc with SMTP id 7-20020ac85747000000b003d2a92721bcmr832325qtx.18.1683262014036;
        Thu, 04 May 2023 21:46:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1683262014; cv=none;
        d=google.com; s=arc-20160816;
        b=Q4Ipyy4zfljHsNH78jrmaoWKO4lDailKTagIPBHr/XHTvB5Qv4l7Q6UVson2cuMp8M
         RdEpRQAA5ZIk8s33jrliAyZYyopUOiOamHOGUS69Uh50u7KHuIrNbOe//ind0I2GQlo3
         ve8QZg7rAGuwnvCv7op4YsVUqEjC13bw7+zYycHatTJQPDgIlMvVNa+mmxQaMpmFcDMW
         3VXmXQyR9l6vUeTAd8jmlq1y6CIw5ubvJwXRp3PQrQmcDwh0ROKx0oqzUN2zUGBcytET
         fK9cU8oMDAT+H/BcsaxxeQiEZ/H8QOtq/XI/SWdP6S3CsPMRL9O9GpW2JZxYjzezLDAt
         2GQA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=Y/F0vs25RXr9WTGsBFx6Aoup88VIapUJs87dwYeO4/Y=;
        b=maMEGyPorUsouagy4+7L+D7E3FuGJOp0isG3HXAoVfAUkx6g7M5MDRQ5/eQr5got1h
         vCBYxuOLvJxEuQlthLhnBQRwAXttP9iNoeDRkbs2xrb0qxYRb7o2V4jn0DgXVtSLO/yL
         AYe5kwgN3a9OKLn8BJ9IcLTLkNFsNObYypXFDIyNkfB8+872a+XDlM3r4uat3XyZaTL9
         9y1K7onUYXAyHggz6s0tJt+tWYwkzijjzU9BsZGJDKhz4jS0YyDqv2kDi5tEkKvauwJd
         ErAo1GeXTHsAPnropz9hov/UEou6WNda3djvWXk0LRbY5ZbyI6ET8CszhD1+IwGIvcUS
         AGTQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=TKQpJU5b;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [139.178.84.217])
        by gmr-mx.google.com with ESMTPS id z9-20020a05622a124900b003f0a7afd790si42021qtx.0.2023.05.04.21.46.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 04 May 2023 21:46:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217 as permitted sender) client-ip=139.178.84.217;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id A5A9E63AF0
	for <kasan-dev@googlegroups.com>; Fri,  5 May 2023 04:46:53 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 17723C433D2
	for <kasan-dev@googlegroups.com>; Fri,  5 May 2023 04:46:53 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 01FA4C43142; Fri,  5 May 2023 04:46:52 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 198443] KCOV: trace arch/x86/kernel code
Date: Fri, 05 May 2023 04:46:52 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: pengfei.xu@intel.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P2
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-198443-199747-xpaxQoGhcE@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198443-199747@https.bugzilla.kernel.org/>
References: <bug-198443-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=TKQpJU5b;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 139.178.84.217
 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=198443

xupengfe (pengfei.xu@intel.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |pengfei.xu@intel.com

--- Comment #2 from xupengfe (pengfei.xu@intel.com) ---
We also found this issue when syzkaller test.
Is there some one help to fix this issue for KCOV_INSTRUMENT?

Thanks!
BR.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198443-199747-xpaxQoGhcE%40https.bugzilla.kernel.org/.
