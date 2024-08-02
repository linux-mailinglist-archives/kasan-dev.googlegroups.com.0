Return-Path: <kasan-dev+bncBCS4VDMYRUNBBK6OWC2QMGQEHUR2A5Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3f.google.com (mail-io1-xd3f.google.com [IPv6:2607:f8b0:4864:20::d3f])
	by mail.lfdr.de (Postfix) with ESMTPS id B2C4794555C
	for <lists+kasan-dev@lfdr.de>; Fri,  2 Aug 2024 02:24:12 +0200 (CEST)
Received: by mail-io1-xd3f.google.com with SMTP id ca18e2360f4ac-81f87561de0sf1102681939f.1
        for <lists+kasan-dev@lfdr.de>; Thu, 01 Aug 2024 17:24:12 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1722558251; cv=pass;
        d=google.com; s=arc-20160816;
        b=dzPicrULtWPT7LV5BoKIhJZfeC0Jo0LvLolZQ45jNxhvkS/V2sDIFvpDRKz7tM0+qP
         prfrQKX6Rw5Pxmq31TSJywLyjKAXSxH6Urj1yqcoNr6YabJuNxDNjqkS18VlmMjhEOV3
         m0N6kTaMMb8wSTpZkey6OPomty5s5GsKdJWzidTaClJLZ349ZBDY0LqiETPGgzUdhM5B
         o3OUPBkxOOQWFUJih8v5a/vsfpfEpKyoPaw/dYD0pRYK0zA/vqxHH296RqOngoWcRrEf
         8D9eHRu+daKWbg2/cBtxZyF952qRg0WKiQQ0tEGs3X7JEtXfcMukwb9rVnfkyLhAv6su
         nEbA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-disposition:mime-version
         :reply-to:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=0KZ5H4HObE0xd7iBKMgi+7504S+8PYuEM37lBNpfyVE=;
        fh=MMmh/vW8KmA3j69Ze2kB1NJxOrVXUA3v1KU8ZyxhV6E=;
        b=yjTUwloBckt8Sj9ZjjewA9gQdoZJ62XIV0YtGDQtrr+ZLCcS5zr0G/cV5Mutd9iFGR
         22x49ateH0/IQq9JPw2y6lmLnkXj3tQwaBzD/AyE0jBpy/W+dWAZPslnbgXikMyMRw5A
         QYYZ8xYhga0sS1Ie710m6jf/WqaMVmkks3ZTmDTW1DClL9un5d3MkBIo4yWCBpjddw2I
         RTorOXk+SjsA0BdbjcnuUm7SmoVq3jw5b3WyLUMykwGXe3NXx9zTjLXKegoHLGxYvITD
         B+rUxCwHJsRtF0uP/UV/La4uRVyrwPTIz+t4P9gW7UaTrD4AcKVtmyAqzfFVOsI9UYDE
         KB6g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YOKDBPbs;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1722558251; x=1723163051; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-disposition:mime-version:reply-to
         :message-id:subject:cc:to:from:date:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=0KZ5H4HObE0xd7iBKMgi+7504S+8PYuEM37lBNpfyVE=;
        b=fNYfNHEzcf+FfRcjNnJ9l+xgEGAgydkwtxtNf3HYBdvy7T4qFiRQIxXUYFDcsKYBtL
         XPybyL3o8iuOztAHrpVdOnOriF9/YdA3Pu7iBkOtb3X818U8k37/E4H9bIKMGZEg9COy
         bEM9aC2d5VsK1ftQSZNd10cRmDbJLibSXtwTMBIp3U9kHGLbuvpTpldL6f6cCSRp82Uv
         DDx2XBUK6xTsJS2ZOFoUCO8Kg7ArpIBPs5m15PzITs9k9Ik7keBcIHkp3K03mqNG0Z3U
         P21iMNMi2DV2efY5pmQZmadGPae06o7wNelRJbkykTMc31uQtchswMVlRptayGuAgEQV
         HqLw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1722558251; x=1723163051;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:x-beenthere:x-gm-message-state:sender:from:to:cc:subject
         :date:message-id:reply-to;
        bh=0KZ5H4HObE0xd7iBKMgi+7504S+8PYuEM37lBNpfyVE=;
        b=M5CEIYy1+kap9Rf2LnIPxlt787RosZc9/70ncK8C83UwVqlz6QXLz+uyrDK1s4SULu
         zjf1cJ89KdqOzlsZWgPJNvRxmnup3BVja3wPtUnAYb+QnakaoQYqr2xo5MDtXdU6hBBL
         LwDl5iBAw/nhmSJGO4iR35VvCb1ivU9sFOHQnPbT3HnOidf07w2CaYBe7mqhLePs5p+R
         o3StJ5dAuAkkh/nAcfGNHuYezYds0dcy1F0l0X1EEcE/A+i7JnzII110xr9CUlsrVXlG
         XVaR1DvdWhtyHnuW/YdV/m+wn6+XkFZKgrdqCQboRwqsXKkBQ+eC8udgPAng8TyD8Cjc
         q2Fg==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV0inaXgCijOyFNpTcBwpWwDc9mOq7cHhbwdq4l4h6tN9n8gbR2rlMBB2TTifdeZXsxafx4AF02wdUbFTa5klIyB+MOro9a4A==
X-Gm-Message-State: AOJu0Yxm1INHX2ix5h4uKTgPQoeKa8V05oS/FohKZo+WWai/8lbk6xIj
	VdSeQqgYIaiotxqq4juWTZqW1lZgiedLEVSAEwO2LVzbZWEBGFKc
X-Google-Smtp-Source: AGHT+IFTRxhZwWzBh4OvxNt/roQRhc7gZ+tvV4H3ZSdpRe1SvInG/LjmoLm8+R5L5hoGQyC0UizYGw==
X-Received: by 2002:a92:d64d:0:b0:397:d9a9:8769 with SMTP id e9e14a558f8ab-39b1fc37fe5mr24099875ab.24.1722558251174;
        Thu, 01 Aug 2024 17:24:11 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:dc0f:0:b0:39b:1836:25a3 with SMTP id e9e14a558f8ab-39b183625e3ls11751005ab.0.-pod-prod-03-us;
 Thu, 01 Aug 2024 17:24:10 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX+3vQCMc/dyQj6mFS+OLNZcarIBdchsb8CjtLSNb7dGbd4J2jnSzPJhPbJY9gk26MEPDwXGpSqd68tA+Wnh8ewCwxxP4p8ewKMbA==
X-Received: by 2002:a05:6602:2cc8:b0:81f:9826:19ff with SMTP id ca18e2360f4ac-81fd4374a3dmr285176439f.9.1722558250308;
        Thu, 01 Aug 2024 17:24:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1722558250; cv=none;
        d=google.com; s=arc-20160816;
        b=i3SbyJZlOoA8HJzC6POxobhFrHTSm4UQu8yacaAPH8xBeBTuDryyRbkdV3bs2TJPvV
         LB2M+tMxlW9VV+Z48Qaw91PCMYUHTfwHlrUiqRileyAGSnEDdFBkMPfT6B8+340FGq3J
         11g+++JWB9WxcapbGOUHeN9NsnnNbbVOCnAa3Rky9Ht3tOkmyrN+O43hc0aZGfQyUDyW
         kT+AH8tW8LMpJyHPONJEkPN9sIuYq6Wa2jucD/v9W4BYmsmsuQVDt1YRA/8i96W8I8ju
         uDaVW2RqbX7vebMYtbQK43b+YmybvWPkJOYU68nN0dZ1fddoLkWXILFIUGfAyp9lZVCD
         BCKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-disposition:mime-version:reply-to:message-id:subject:cc:to
         :from:date:dkim-signature;
        bh=Mai6ORAnI1MdAxeR/9csnwMrvs/MHXEMsg67pOemkIU=;
        fh=FM6+x405secWhB0I/fURJ9qcCgQgJ9bBxtQjt2ii3CQ=;
        b=V/lqYOZK6qScEdi0/1nlamhxrrsJ5J5KVvyEtNJhxX5kppDPOe1rqGLgMAhAe4FazP
         DFneJEr9VOk99MulWmOzadxJwJPBRBuwyL40HG4L5Ee7xm2vewl/2pgYbgYsjVyRM5uc
         o+JD1GhZynL15n6tkWmNK1vO/llHQXs0S4NOFrb1JbZGJVWCp91d9ZEomzdEI+NkmcIl
         /rMNhFXXRijiRPJhcsBZyFkQ/MDAqREomBpwKgw7DSeF14TBTuyUHebdc3h0Tceunmz5
         W/UObsLXMkO6csCr9tpa5VRfzz2x8c15g0+h/19RJ80AN2lLarkdGj+C8UlDCry0yWJY
         0DTA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=YOKDBPbs;
       spf=pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-4c8d6a3ce52si34089173.6.2024.08.01.17.24.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 01 Aug 2024 17:24:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E485462943;
	Fri,  2 Aug 2024 00:24:09 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 930DFC32786;
	Fri,  2 Aug 2024 00:24:09 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 3A90ACE09F8; Thu,  1 Aug 2024 17:24:09 -0700 (PDT)
Date: Thu, 1 Aug 2024 17:24:09 -0700
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com,
	kernel-team@meta.com, mingo@kernel.org
Cc: elver@google.com, andreyknvl@google.com, glider@google.com,
	dvyukov@google.com, cai@lca.pw, boqun.feng@gmail.com
Subject: [PATCH kcsan 0/1] KCSAN updates for v6.2
Message-ID: <b5ce4d12-e970-4d84-8f89-fd314e42ed30@paulmck-laptop>
Reply-To: paulmck@kernel.org
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=YOKDBPbs;       spf=pass
 (google.com: domain of srs0=masw=pb=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=mASW=PB=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
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

Hello!

This series provide a KCSAN update:

1.	Use min() to fix Coccinelle warning, courtesy of Thorsten Blum.

						Thanx, Paul

------------------------------------------------------------------------

 debugfs.c |    2 +-
 1 file changed, 1 insertion(+), 1 deletion(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/b5ce4d12-e970-4d84-8f89-fd314e42ed30%40paulmck-laptop.
