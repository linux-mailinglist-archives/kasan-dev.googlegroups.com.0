Return-Path: <kasan-dev+bncBDCPL7WX3MKBBIH67LFAMGQEG3RKXSY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 6675ECFFF3E
	for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 21:16:35 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id d2e1a72fcca58-7ae3e3e0d06sf1818691b3a.0
        for <lists+kasan-dev@lfdr.de>; Wed, 07 Jan 2026 12:16:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767816993; cv=pass;
        d=google.com; s=arc-20240605;
        b=gZu3DnnfxjU8p0lwA85l+EDTsElNdAta5L1+cR6+qFv4n3UpDBs5ChCl162nQ1iMdD
         WaylBeLFoCmfmsMfuFL3a/iKTGUWZI9VW62YmOSvMzQagKD99ukMWrysaIkSm8JtfZ5R
         mV0nv69FF1XL+voDtanO9FTImSiTni/6ip4ojOnmbzkBI651tA3v/3M8yBgdmG5ZrfUZ
         1VqkbZaivjuYOKq06ZPElymly6NlegM0YgdQI4C7lPplQv/u8fUewvGirQY5E3dhZjSx
         xn5XTB49zJbwGj1ZVIN4AY5LvGyzJudHm4B5pfjkTxhjB4glQvqa+E7ltoIGi9+s+wZY
         7H5A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:references
         :in-reply-to:message-id:date:subject:cc:to:from:dkim-signature;
        bh=fw4L8qSAvtkX0ft3W3eJZ39qDRMMKABkAI9roG8aUfg=;
        fh=YoyoKNCh4VDBmoDkNX6OmJA8+KfFJ4+d2+C8yL+w8FQ=;
        b=D5MLqFckR1Z+vITlM+9ry3EBu9kjK5q7zoKvtYfvECZEaulIuSAEkH/ZlElQFbWm7p
         5v3tsiENOdzx46m7mFOpXXrt7UMPhd5SOwDr+89CvH7OnsZYW07TmFISb9LNMGjoSiIu
         1IoYLRPEumURhZTNsKjG0cGoNdMGTV91909rQ9k8mPp37SYc9UQAM1n4k1kT7U09QRkN
         uzB6JbvrfigqgY4gBeO5l2fLz3P/18lh9OU+26I/4lRiX3ulYu0xf0rCzkcaVMow6/me
         4hWwwqt8YD1kg218bo1Dn5DBfVr+/mCpkxb4FrR1TQCEnND4lt53IcKrpeGqT0rIUat8
         BbPA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=raoxuYrp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767816993; x=1768421793; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from:from:to
         :cc:subject:date:message-id:reply-to;
        bh=fw4L8qSAvtkX0ft3W3eJZ39qDRMMKABkAI9roG8aUfg=;
        b=Wl40697jd4I6MCP3SBfqVedaivC/UAfB8/Ux3mTsVjMXY6zXqMXmxLRT2YrvgqlAtA
         CBRzKATYFV2hWoHasBxrVJjyfPJx8nZ6d0YpQsQzxRTueRUKfiOGc42k5220G3VwI7yp
         KM9PwOJAq5CIPetJXUG9zzEYtoHfUYEHubmUnzmqae+0An7LQiCziOFh4d3CLAe/zFZ8
         cYTQ3MBHxm8SxWZXEN0ZoL97sWwWUOBjzvxug26wqH703IXjWMjUZMuH7esTrL4SBlUQ
         ua/KoBqQRrpj5XzrDkwIVVtUeG3PpFnFEvheDe2EzhIcBIeloxeGVHT6S/QxiOpmvvCO
         GapA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767816993; x=1768421793;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=fw4L8qSAvtkX0ft3W3eJZ39qDRMMKABkAI9roG8aUfg=;
        b=FnNPq6c63R8J6VkyoOHPfVyt07dhaFe8VZ2mygjOTzSoYznNxNStXnFskJhlRVo4op
         jJCTHrT4O2Zj5gmN64xEMWbFeVOHtbCoL5o4LkD7CrWkry7rblJfBgY/UcSJ7dO/vUD0
         Uc9ogpwhHFpZnC2s0CmbjSxXI/gfmJ57qAeVS+SkUBPUyW7i70IXMdUN16LFhGmeW6KR
         g3+HVLWmV0A3/r8G4FngZ/gjyeMSnjDSk45yF3xOnsX6yiCjcQxEl0riYaVDfhtA1/Ne
         hTRWkiiXuBgb9MlVFQuebPHmjdCfqp3fFio0f5+OI8JBcRVE3x8KVCffkmLTPeozFCAe
         G9MQ==
X-Forwarded-Encrypted: i=2; AJvYcCUJ/6nSk/BTShgJ6cHFO0I7GaeWWMjJrcfQsDNJUC/yFVrvNuZSkpyulMG3ci16tilyvDOhkg==@lfdr.de
X-Gm-Message-State: AOJu0Ywof22Nvs7Wnfl1eIGVCrxjC4ZRZrPCkDm16LlcEWN1/SqtAJt9
	sOfqkzTmm7l5PTziu5Du1h0T/EA01Lr0p3Ry6cJs0gkLzVEpjIc0rTve
X-Google-Smtp-Source: AGHT+IG9C5OxqQMjt5lOIW/6kSgwheEDyxRDn+qQXsTWbd9R4xjEfvOKjdwBVIGIUkolq+ij83B0jQ==
X-Received: by 2002:a05:6a00:1d8e:b0:7e8:4471:8df with SMTP id d2e1a72fcca58-81b7fbc8d85mr3352982b3a.64.1767816993307;
        Wed, 07 Jan 2026 12:16:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWaRXftdlSwWJ3lFHNgjsXng60T6Ygj44mZgIu43luRTqg=="
Received: by 2002:a05:6a00:8185:b0:7b1:eb6:10d4 with SMTP id
 d2e1a72fcca58-818767f3438ls1704730b3a.1.-pod-prod-04-us; Wed, 07 Jan 2026
 12:16:32 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXwrh09qSwrgzmpJSLZ0hewhJ5/t95zgRiLMTciQ9hkjZb6AAK/U1FKoNF4Tw3C+REMSzZXd59ZvoM=@googlegroups.com
X-Received: by 2002:a05:6a20:2454:b0:366:19a5:e122 with SMTP id adf61e73a8af0-3898f84815dmr3175280637.2.1767816991927;
        Wed, 07 Jan 2026 12:16:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767816991; cv=none;
        d=google.com; s=arc-20240605;
        b=hlhdszCjYhjYLvJ/J1Eo6lxGiXw/EzyNnNeD8TFiwXHtfeG+THuUBbi5Z93RFE1n7B
         Oo7f6XMimhwx9xiypbZnLqkTx8ujdBgUlccGgRioU/3+/msw5MMt0ouFWBTzqszX+3Bv
         0d/uN8Y0D9mI349avB6Z7qBq4SGNlEWhS0PiokAW5CXyhszjIdkmJA02FU7DzmI5eqcW
         Orp3689uwwe4lOKpEgmTPzltVSkQbHUNcb8cZSbacN/HoB3+WfFKfnkSaO4t7tfV2mKu
         pjAc9Syy3KLFFBhCjvfw2p1ZH166tKR+I2QWMmqVe8udF2iQdumLXPYOhae5GtBpv2pq
         7Lkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=KdObwX1cCmTsFwH+01JHU9wx9uzjk0a4Y9ZTq7u1MvU=;
        fh=wwg8Mgyr7pv4iuOAC9i3S4uArKnfFOiBuMUJ1jvEnis=;
        b=gS5UZ0QoRvGVY+0fXP3Mo5rzjkLjJgNQBbj/QlO1UpICe3m5VY9t+VIvBjDPJrzN1m
         u7Q3gssnqpAazvspmAsU326MNXbZqhahFS2FNKAksW8avYW1n5MSTYqFw0t1n2wynSQK
         dNPi+5TJxYYkpSqZ7WEl6l5zJJkRqulk2oCOeIAyOyevpZdN80lxDxlxNWyATXXG3XY0
         YvQ6sZwttUX/cM6NeUcXUda7uHtA68FkyUkgozRoqG181PSoCFCybQAzRs4ZFmr3BgZu
         MEUOYAHRLp7yYcjiJ/+WUKWiakyZ7hUbYUqX52AUG2wFAq2RB5iGfEGHI8BQCe+M0GRM
         f/+w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=raoxuYrp;
       spf=pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=kees@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 41be03b00d2f7-c4d9403eeb3si146883a12.6.2026.01.07.12.16.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 07 Jan 2026 12:16:31 -0800 (PST)
Received-SPF: pass (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 9E5014013C;
	Wed,  7 Jan 2026 20:16:31 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 739CCC4CEF1;
	Wed,  7 Jan 2026 20:16:31 +0000 (UTC)
From: "'Kees Cook' via kasan-dev" <kasan-dev@googlegroups.com>
To: Stefan Wiehler <stefan.wiehler@nokia.com>
Cc: Kees Cook <kees@kernel.org>,
	Marco Elver <elver@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	kasan-dev@googlegroups.com,
	linux-hardening@vger.kernel.org,
	linux-kernel@vger.kernel.org
Subject: Re: [PATCH] Kconfig.ubsan: Remove CONFIG_UBSAN_REPORT_FULL from documentation
Date: Wed,  7 Jan 2026 12:16:28 -0800
Message-Id: <176781698614.1598418.16480180348554919684.b4-ty@kernel.org>
X-Mailer: git-send-email 2.34.1
In-Reply-To: <20260107114833.2030995-1-stefan.wiehler@nokia.com>
References: <20260107114833.2030995-1-stefan.wiehler@nokia.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: kees@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=raoxuYrp;       spf=pass
 (google.com: domain of kees@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=kees@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Kees Cook <kees@kernel.org>
Reply-To: Kees Cook <kees@kernel.org>
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

On Wed, 07 Jan 2026 12:48:33 +0100, Stefan Wiehler wrote:
> There is no indication in the history that such an option was merged to
> mainline.
> 
> 

Applied to for-next/hardening, thanks!

[1/1] Kconfig.ubsan: Remove CONFIG_UBSAN_REPORT_FULL from documentation
      https://git.kernel.org/kees/c/1d1fd1886912

Take care,

-- 
Kees Cook

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/176781698614.1598418.16480180348554919684.b4-ty%40kernel.org.
