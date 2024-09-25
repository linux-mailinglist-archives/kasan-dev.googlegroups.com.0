Return-Path: <kasan-dev+bncBAABB5V52C3QMGQENNWE4HY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id 480139860BE
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 16:32:25 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id d2e1a72fcca58-718f329aefdsf6801920b3a.1
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Sep 2024 07:32:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727274743; cv=pass;
        d=google.com; s=arc-20240605;
        b=ChtKChDGvRg0OKIaOinj9RK/JuD32VFYmJ+6KyUi36Kf9tBD06+gPqmRdrU7nzOa0T
         T8/pqcuzDLmD5Mw9PHEgI4cxZ0WcxQ5J8DLYgo6Ho+dzJS9/BJwTYs3gbaopFzxNtRw1
         DYZnMu1pAhBaivfBJu1G7EyWADpCNysC6adbv0q5ji8TD44lzIlh1wcs0e7PRaPkyacP
         3+P3at4hUk26dHBnxYvuFVIl2K00XXnzhgWCSYTWQi/awESUW2G0uyM56D/yfNY+sML0
         2zOFKOOWFozn+QNerIptaPFcLL2RHcT+IVeIV8CpDtTCCDJArhyXrElz7+UQRHR4ja0x
         cAHA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=Wh4F+wnjhSEc97YQzDwJNWwp5YcXmy8dgrOf0tYYZWQ=;
        fh=8J5UZpkJs5UyT9Jmb21/H94MFdfhUmR9eCzZ6l5aDOM=;
        b=ACcVyX0Kqrf9knTIuQAquz5oCtPKOxr2K8HygB1gCuxcvUa86swb6UxSBM/7gMGC2V
         8rUX9sVU6tKH1mNVxsaoPxdpHPCugoJTN1X2IFSZa7Qkg43eRH7oTwcpJI0mFwdsDP1y
         yeLYqaiZX/g0jz+tOeWxdhwxUSIb9w420nXks1XOkzuvyR1eGkS5uURG/Jwi2hAgV3Jt
         cgWQkkf2d+/okh4OH7gFDGJquXbDz0+c240fTaYhxjLZR9NITb0La6f/8OHy4fH3pNHB
         4wjwSV7V/LNLqnBRG0Dnli8olTMUbfi0LGKcFFnYZQm8UsgPKqODT1NzT+YSt1LesSgS
         VPkg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=GqQdF3hL;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727274743; x=1727879543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Wh4F+wnjhSEc97YQzDwJNWwp5YcXmy8dgrOf0tYYZWQ=;
        b=fWHqhTDrZCFLSYywKhwSfU18PPi0I7UGw9pn4T5m7Nji68Gaxla1YSlgteEyD3UdH+
         Z1sHtTt8jg+M9RPv/wJUkDWA/BlZ3nZvT4y4UVXRH+mVbmb+tu9B+Os64AOb4eDWd3i9
         /qoC0eLygpIrjthLDHdu5ckuZmVHa95MuKepXXTlueWA+Voho6ced6bV3IcBgySav3TP
         sDlUszTrW4isuxWJo+wk0u5RDlQpqp1rrmPimwr8d8/pTJWbBac5gz0HAOTipsBQnomU
         kXXgU6x47FTMgFHr9MEPbis4Z2osmInblbjOl0bTsv62P7VmnzQZXAD4JNpZAkd7d7Sk
         znlQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727274743; x=1727879543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Wh4F+wnjhSEc97YQzDwJNWwp5YcXmy8dgrOf0tYYZWQ=;
        b=YRnVcXGM0s7WbEuucZxsEvwgmcmaGlyXd79Tn1FeSDSOhOsdy7apA78s3q4b+kfEte
         3iwgpc9C6gaLHFQXPfgpPvlEanzw3Nvf9kQ3WLrbiXcS6zCd+AXHPWrhVHmnqCJxjRaD
         JcsiVYFbhSLtQzBoVJxdd9y/DZ+QfMDMAWMUiEQOsRay6YQa2h8vDw3NyhaooQkO78IO
         rLx+gOeXjfz3wtlUQ/dycpWc0uzbf1oiAIDVdZWP/mjq2TgkTXmfl71+DgELuL9zBob+
         PsQYXPbQdtLhxHUMw+QxQUbFvXVh5SWv3EYcPTV8kDMo2K0TxZd9+dI5eHWogj8g8W/E
         83mA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUBxORGeoEVfB0Lpq8dtkGjoQLa8WBE9XPU75VoPGAxn51M8ndCT0P8BUGKJ3un2kVzjpDD1Q==@lfdr.de
X-Gm-Message-State: AOJu0Yzl5SAse0HhC7z53oGhoWF7ppm8c2D3/TJ8g7NMF+a3e8tj4yB7
	BoX89g0OHR71enh2WU8ddP3hJNwIImsw1h5IzQt8SwYcDoAocZXF
X-Google-Smtp-Source: AGHT+IE3ex6AxinQ4ygE8GR/hcEJ6uuBzqfwNsLTc6EtTPeInvOX0QPB7JEUJz8LKSJM0vqS+JYEjw==
X-Received: by 2002:a05:6a00:181c:b0:717:8eca:95 with SMTP id d2e1a72fcca58-71b0ac51691mr4415069b3a.17.1727274742452;
        Wed, 25 Sep 2024 07:32:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:b81:b0:717:84c3:c2b with SMTP id
 d2e1a72fcca58-7198e31d33dls5414502b3a.0.-pod-prod-05-us; Wed, 25 Sep 2024
 07:32:21 -0700 (PDT)
X-Received: by 2002:a05:6a00:399d:b0:714:43d2:920f with SMTP id d2e1a72fcca58-71b0ac7fd60mr4078999b3a.25.1727274741338;
        Wed, 25 Sep 2024 07:32:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727274741; cv=none;
        d=google.com; s=arc-20240605;
        b=cFEHEPupvudPMpR+ZW0/9C+hJ0FN6/3MF7LhEV00tRvKX/Vv2+rf9XL/qy4K2cJK1D
         qcrD/bxIdwaFLFCVvF7ScphSx/eA6PIkFida3C3xlZ2TTh2ZW17VJZSvpzplOTjcdtgo
         QTwh0P4vgDsDa2O3C+3TXgX553ZLpcnd/9Z6NpUWYiiOiBaStrWTAsGDZcjYZGklAzlc
         Kic/h0HCciO6Ir6BXnGNb71j5TXAezr/LIq8LTWviLyiAs/kPmA6hdIRTb+AVW7odtWS
         9Rg4iVS+pi98w3Ie+L49i3ixPn6fizTnyWMuZXA9QALuYSioLd4RrCAueAdrBTNElC0h
         lBYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=BsZEUeQ9k4bTBrNUrJok+wdi+IT5a6ZQC1jhpS7yGY8=;
        fh=soLd1rxl5Zg4+HEDKR/GyOBvVj1EgNzTFg1l3c/vbe0=;
        b=gUlXDzH6Y6pFEQchueeGAzAGQ0x36ELXWUoWE0hCv384vdSmnxHDEelikNa+UCC0oN
         UaTLLU9vYjGxB1tIKJKa9gNbd2hBDWJ3KfiKlT8dlQzySLNBlHdId+wgUv2w9zkSsbPJ
         hN76u4gS17Z1GiNe42G/Ac+8kzhdeHDJ4SSp6zu3TS94ffkKBMAPDA9h+FGNzIZfSw67
         UT0jmApxENjhElvLOSWx/ShP04NztG/r7W5dhoss6Pas+RcHp5I65RCDTMo4Lgr6acxZ
         kCzTU9WlfjqZpLtUYIJU+RrwnpFYk6uCksS2pKgp95zS4hYxqCRwv7PuLdqOUnvkCmQN
         +p7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@163.com header.s=s110527 header.b=GqQdF3hL;
       spf=pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) smtp.mailfrom=ranxiaokai627@163.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=163.com
Received: from m16.mail.163.com (m16.mail.163.com. [220.197.31.4])
        by gmr-mx.google.com with ESMTP id d2e1a72fcca58-71afc72c848si184510b3a.0.2024.09.25.07.32.20
        for <kasan-dev@googlegroups.com>;
        Wed, 25 Sep 2024 07:32:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as permitted sender) client-ip=220.197.31.4;
Received: from localhost.localdomain (unknown [193.203.214.57])
	by gzga-smtp-mta-g2-2 (Coremail) with SMTP id _____wDn9EXeHvRmGMqpJA--.33673S5;
	Wed, 25 Sep 2024 22:32:06 +0800 (CST)
From: ran xiaokai <ranxiaokai627@163.com>
To: elver@google.com,
	tglx@linutronix.de,
	dvyukov@google.com
Cc: kasan-dev@googlegroups.com,
	linux-kernel@vger.kernel.org,
	Ran Xiaokai <ran.xiaokai@zte.com.cn>
Subject: [PATCH 1/4] kcsan, debugfs: Remove redundant call of kallsyms_lookup_name()
Date: Wed, 25 Sep 2024 14:31:51 +0000
Message-Id: <20240925143154.2322926-2-ranxiaokai627@163.com>
X-Mailer: git-send-email 2.25.1
In-Reply-To: <20240925143154.2322926-1-ranxiaokai627@163.com>
References: <20240925143154.2322926-1-ranxiaokai627@163.com>
MIME-Version: 1.0
X-CM-TRANSID: _____wDn9EXeHvRmGMqpJA--.33673S5
X-Coremail-Antispam: 1Uf129KBjvdXoW7XF4UCFyDWr47ZrWxWr15Arb_yoW3twbEq3
	y8Xw42qr1DAF9rZryqkrWrXFZ5W3y5JF4Sv3ZFqF17J34DJw43KFZxWrn5Kr95Wrs7Gr4Y
	k39Ygwnxt3s2kjkaLaAFLSUrUUUUjb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUvcSsGvfC2KfnxnUUI43ZEXa7IU8iZ23UUUUU==
X-Originating-IP: [193.203.214.57]
X-CM-SenderInfo: xudq5x5drntxqwsxqiywtou0bp/xtbB0gdlTGb0HcIXZAAAsC
X-Original-Sender: ranxiaokai627@163.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@163.com header.s=s110527 header.b=GqQdF3hL;       spf=pass
 (google.com: domain of ranxiaokai627@163.com designates 220.197.31.4 as
 permitted sender) smtp.mailfrom=ranxiaokai627@163.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=163.com
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

From: Ran Xiaokai <ran.xiaokai@zte.com.cn>

There is no need to repeatedly call kallsyms_lookup_name, we can
reuse the return value of this function.

Signed-off-by: Ran Xiaokai <ran.xiaokai@zte.com.cn>
---
 kernel/kcsan/debugfs.c | 3 +--
 1 file changed, 1 insertion(+), 2 deletions(-)

diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
index 53b21ae30e00..ed483987869e 100644
--- a/kernel/kcsan/debugfs.c
+++ b/kernel/kcsan/debugfs.c
@@ -181,8 +181,7 @@ static ssize_t insert_report_filterlist(const char *func)
 	}
 
 	/* Note: deduplicating should be done in userspace. */
-	report_filterlist.addrs[report_filterlist.used++] =
-		kallsyms_lookup_name(func);
+	report_filterlist.addrs[report_filterlist.used++] = addr;
 	report_filterlist.sorted = false;
 
 out:
-- 
2.15.2


-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20240925143154.2322926-2-ranxiaokai627%40163.com.
