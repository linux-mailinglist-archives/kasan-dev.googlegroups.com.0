Return-Path: <kasan-dev+bncBCS4VDMYRUNBB7VJ4SGQMGQEPKJXLKI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id 1D6A7474D87
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 23:04:47 +0100 (CET)
Received: by mail-wm1-x340.google.com with SMTP id l34-20020a05600c1d2200b00344d34754e4sf1017965wms.7
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Dec 2021 14:04:47 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1639519486; cv=pass;
        d=google.com; s=arc-20160816;
        b=fF7bhTPhnsgffsma1gsnbHgCvN6LJPMxVoYpoUgng0tgcsWx6G6RxwrbVz48K0iOkI
         g2tescxvUseeMrAxuYHfGdssCj5rbvja7soLHiJMQU6Hw1ONbXUK2+4EGciuzmCOF6fs
         /IytJhQEagnGE26TEV63XP70R3OXHDTwoxVZHQAvpkaUog1J5ahrnXgS++zmkheDUBjA
         xG6M1juYpkTkUrzclSwAuEV9hQ4g4giI8TOHd7OOs1n9IYfZWv3Emv1kGQ3tK7G1q3i6
         ScOlRsmpe+V1DIYBD2Blw9k9ayFx/RRwg4Ox82kFnPTjV8U5qeM1IFO5xh994kQvZS6d
         3I3Q==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=THI0lLqNGAv8I+MMMC4CTs41wsQMlQvfTwJWwDyHKZA=;
        b=txxMi1dPQLi+1QyMQgR18JZCFgkoGEKdsv/dSdY8+SM2Uh68imFtmiJb/hNtQqUUzj
         vrDII3LI2kOkDohVHeSjamoO+rguXs984ASNnYID1ZXuzN3+WkIDI49PQStpX91vcJH4
         BhgsNwUEFIhmj0fHWeRv6G3cGW8pTYehJLKKdWmjlVBOiN/QkV4tGSxJPYXlAgJw38Po
         A5zUjNves66+1Ukz4Y2J+ZdXro+FecqLYO4Exc14lEz5BaVQi+XPYz+3z/ZzW0iBRRlZ
         oUuyAz2hOxOV5ydSr2521OnsYqv9OnVbcI6MAOIa3t4nk51HK6CxDGw1hMS4J6BYqgSn
         UEVQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JEpl8RaL;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=THI0lLqNGAv8I+MMMC4CTs41wsQMlQvfTwJWwDyHKZA=;
        b=HrW3f1PxpMVKwwPAAawia888unVXN5eMOhLwsPEjTeG+cKG6NSEgZujRN7ZjnwDiX8
         eU5dXtuJETI+TsioGLfKsx/JLtSWTH37C09KwG8wBiKCT0Soafp1z5LJmDEFvmfpHLc/
         v0zxWGLElmXeLXjDMslyxQN46xPF3Xmf2CfVboG0tL+khQi3tcdGbmnusdzISF9Ci0lb
         nFTRC7eHEe/V+9oBM2UgbXd5mXBnFXvjelK/8bxoeRFNv48BXGmDAWNf4Kq8m4q9nXIQ
         Efxf8G7WZmFdB/i6X57eWaJ+QDG6b2LyZqVdNoVazzWqAWoEONBzbqZuPaeCthz5av/g
         otbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=THI0lLqNGAv8I+MMMC4CTs41wsQMlQvfTwJWwDyHKZA=;
        b=eRUgknYQtrqVpnY9fXYHyTnJdQRCSzMmJgN/qtlQQrur/++L/2kvJkvSctNbiIfWxM
         AiffktlkjUgAoY7wl93WlxtuCW9OS7OZIy0iim8fieQ8TO12/l9RAIh4KOSqUl8M9YzM
         tZKkhuDYPio5+vxcTKRrYAlQlx1JKuFgdswWMcFQLS8iTcg0UgynQisUIJY4M5v6ekMd
         EyUcAWLfgGnbjzumOnfuimZaAbXZzgbREj5apIWj917WFXI/FMHxi5wLYdkmjsgBhjQu
         y0Txpeqlv1FBXu7zgHPvgYnygSSDcnou6KV/0/kwDfD2zG/eMpq2tP5mjTf5yKcKJp+Y
         tqmA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533j5GV1NjmZtrrnh0z09f+PkQi74QEgmv4A+twCjxcRuT5Rf23J
	pk/t7c1IdZvAF0ClzWEGCyk=
X-Google-Smtp-Source: ABdhPJzBGxWnHRqfoZ87uHwyVyUzkzqgzlXmvSqHa8e8qDeUTZICtjvtSlqylpbgVvkNOfoE0LWyIg==
X-Received: by 2002:a5d:5005:: with SMTP id e5mr1716713wrt.700.1639519486858;
        Tue, 14 Dec 2021 14:04:46 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:522c:: with SMTP id i12ls211710wra.0.gmail; Tue, 14 Dec
 2021 14:04:45 -0800 (PST)
X-Received: by 2002:a5d:6da9:: with SMTP id u9mr1681549wrs.237.1639519485857;
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1639519485; cv=none;
        d=google.com; s=arc-20160816;
        b=lRHbnt25elhkN2qXKJZh+Gc7CnbBicAf6DzqmH7hcZN95RN0xYpkjMCu4wgGZ/YCDi
         ApMFgTP8CVmRy+D5TqfqL45MxXpljVjUJbXZPPJvSMB3fsOyubknDDX3P+1KSuJFxIbi
         aMgzfn9kgzHmGfonoToKLyYYR+LBzSxYG5mTATCBVBXYeIHuxLNH9Q3hwsWUGeoSeH9W
         erJTn6BDuaP8XA8Xgba6I+5KqRN8bzldKZy1QQpxoU+s2gVHi+amU+37ja8iF7eTtM8M
         TXmp9Gcamees/HemR4cZfYaeyYAXW9v1bDlZ3c3jJCL1UbB8+kAoF4Y2cDfH/6b4kfC4
         D1cA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=kHfInG5LfZqU/4K3uNH0hNqf5vdPAMEx6Wa3JoyCxFs=;
        b=F5PKLV7jL07iPIl0CFXx6VhDYkHvnzC1non5hDOWz7FA2pp1fLFjJHRRkqKWSCmw62
         7eIUCsvEkBHBrfRNSHn0H1uWQiqYNS99xwHk+Hu3F+2L90+p9VrfgvvMj01yUglE7QNh
         Qii2ywYzgAvLuGg38+VXSrPcxyikIiOesXXPbzsQls1vJKoub/MiDgexLcVhlwg4h41B
         mEkwMd8iuTji1W6JIg4IP4rj3rN0s+8UfarOpm9qjinIRC+3TxT0r7sSrTygUArbqjfx
         2sWZpJF/jqd+ewg2VnzIC2HtOmIFmqmu+3fv8VsBJIb70Y2byQI83eBIsDbZyyBXjdC+
         A3wg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=JEpl8RaL;
       spf=pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id o10si146781wmq.2.2021.12.14.14.04.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Dec 2021 14:04:45 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by dfw.source.kernel.org (Postfix) with ESMTPS id 1F5F061751;
	Tue, 14 Dec 2021 22:04:44 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 2A947C34635;
	Tue, 14 Dec 2021 22:04:42 +0000 (UTC)
Received: by paulmck-ThinkPad-P17-Gen-1.home (Postfix, from userid 1000)
	id 7EB695C1E82; Tue, 14 Dec 2021 14:04:41 -0800 (PST)
From: "Paul E. McKenney" <paulmck@kernel.org>
To: linux-kernel@vger.kernel.org,
	kasan-dev@googlegroups.com,
	kernel-team@fb.com,
	mingo@kernel.org
Cc: elver@google.com,
	andreyknvl@google.com,
	glider@google.com,
	dvyukov@google.com,
	cai@lca.pw,
	boqun.feng@gmail.com,
	"Paul E . McKenney" <paulmck@kernel.org>
Subject: [PATCH kcsan 19/29] x86/qspinlock, kcsan: Instrument barrier of pv_queued_spin_unlock()
Date: Tue, 14 Dec 2021 14:04:29 -0800
Message-Id: <20211214220439.2236564-19-paulmck@kernel.org>
X-Mailer: git-send-email 2.31.1.189.g2e36527f23
In-Reply-To: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
References: <20211214220356.GA2236323@paulmck-ThinkPad-P17-Gen-1>
MIME-Version: 1.0
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=JEpl8RaL;       spf=pass
 (google.com: domain of srs0=oav4=q7=paulmck-thinkpad-p17-gen-1.home=paulmck@kernel.org
 designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom="SRS0=oav4=Q7=paulmck-ThinkPad-P17-Gen-1.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Content-Type: text/plain; charset="UTF-8"
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

From: Marco Elver <elver@google.com>

If CONFIG_PARAVIRT_SPINLOCKS=y, queued_spin_unlock() is implemented
using pv_queued_spin_unlock() which is entirely inline asm based. As
such, we do not receive any KCSAN barrier instrumentation via regular
atomic operations.

Add the missing KCSAN barrier instrumentation for the
CONFIG_PARAVIRT_SPINLOCKS case.

Signed-off-by: Marco Elver <elver@google.com>
Signed-off-by: Paul E. McKenney <paulmck@kernel.org>
---
 arch/x86/include/asm/qspinlock.h | 1 +
 1 file changed, 1 insertion(+)

diff --git a/arch/x86/include/asm/qspinlock.h b/arch/x86/include/asm/qspinlock.h
index d86ab942219c4..d87451df480bd 100644
--- a/arch/x86/include/asm/qspinlock.h
+++ b/arch/x86/include/asm/qspinlock.h
@@ -53,6 +53,7 @@ static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
 
 static inline void queued_spin_unlock(struct qspinlock *lock)
 {
+	kcsan_release();
 	pv_queued_spin_unlock(lock);
 }
 
-- 
2.31.1.189.g2e36527f23

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20211214220439.2236564-19-paulmck%40kernel.org.
