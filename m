Return-Path: <kasan-dev+bncBD3L7Q4YQ4LRBMWFUSNAMGQEZDBTJHI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43e.google.com (mail-wr1-x43e.google.com [IPv6:2a00:1450:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id EFEEF5FEAFA
	for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 10:49:54 +0200 (CEST)
Received: by mail-wr1-x43e.google.com with SMTP id m20-20020adfa3d4000000b0022e2fa93dd1sf1671694wrb.2
        for <lists+kasan-dev@lfdr.de>; Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665737394; cv=pass;
        d=google.com; s=arc-20160816;
        b=sI9q2SK4dAJefudpFfiQi0aGrwKod3KV7ApKBLI0gdlEFgTHytgGkZqDUowGsg5/11
         zNY40IgVg8VPy7lr78ywe37udy+uyEWjEapvB+Jk4vcBMRyPVwZChyfWUNf8jBsnNBe3
         z4NHjG+6adHkkFGIcFbOcwc4GHN8pqkZb/av46ACE+WIIpJD1E2Uy8EOub/JFbNSP4P4
         MR9MeDrxa6NNjeHqQadgWfcqwQ0voHvD9j0Wn8LZLLwXwYarq/PNoYv7bFz+4ztpbl8s
         /ypi1x5T/Ypt8iH+JO0xuefiv1eRWBmxgswIn27CfIfZ04cj/NUuYR5R8loVeH+W+Iz8
         lkcg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=QuII7OeV6TwzsOFJ0lZ2z+76+QSkx//ixRu4tomi5Fo=;
        b=Mp6MhO+HsHSKc7Us/reIK7izDQzNPbWPK7oAsk4/8RWU+HhuasRctQSvKI/duxiy2I
         jkdVWEh2IZwoNGPR6fMUiv/YVCmn/nbgHRObro9d33y4kQshLc+ibev9cw/vBdDnEVdW
         X/aQ5GIPrsHV619y9yT0wjl4Ni0G2JoEF32DvhjglFnGZJlbRQiWAPlhYsHve1FKiA0+
         +RnoCUdtuVaa+SxTq+xepPNwzRt++Rwwt6OAi9gG/pD+1VRWAw5WoHaZ7+qKgFU+ywdC
         THRRFpQrKzfBspIX+6vaf5CfVaYjERSNE7yccf7O4VFa/xSQRpUS2xk0FAvxIUWI0Vr2
         TwqA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aQXy8rp4;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QuII7OeV6TwzsOFJ0lZ2z+76+QSkx//ixRu4tomi5Fo=;
        b=iNlA8DyuE3zk4bpcnkvhtXZfmJHS9UDgvCXCuYAeCPPiwwxAQdVMwBYS2P7Os2Vmk3
         g7lQ8fCzWznWApnX12BEX9AaLa9lSfmdM8dWvsuRcWH9saQ0uOThx90rycW5xNjT7gZu
         EjNTZGT7ZobYU6Lo7y7JEb92SMQi2js5FyUOf/OuzLZgJW4ChFJqaidRO7nBnH6iSHfV
         z9LsSUmqj0UICK7UqX8IXFzr/M4O5/xBOyKpvMWQ9gmJYlVP9+mt6L0t52iiJtFE6wV6
         cUTB7bwOQW1ROTV1Jh82cvEL3/RoeOQMdNMy+EUzxGewmWLCm8lZVAjRQwQGCkfZqYvU
         gwNQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :date:subject:cc:to:from:from:to:cc:subject:date:message-id:reply-to;
        bh=QuII7OeV6TwzsOFJ0lZ2z+76+QSkx//ixRu4tomi5Fo=;
        b=ZZEuVHLtjd405a9YZV44qAsmzHB5bQMNc8e61okMhzUkWWgtsK+i68wbz+XRNdU1pN
         xVOfH8Z2BeSmTDlOpfdWRGsZBzfBdNzu2TfnDAdXBv9EULJa4aGkdkHZ1HakFO4QRbEy
         UgjSlwxjMIME8/Bs2IdR95e06ixKp4gK+6Gltd8QiSH82AAb2XQqJignYAMm4JNBxdvf
         YPvj7WuZq03jVssXEPFZ2nTmV6hcvGxPpRPpzC9Yk59Tg7ROwBrr6q3Zm8rHYMgkev9P
         e4DIPAABJ55Sc3JXeCEA/ShV+avpsl7Q9EwixXUbciGGqD2EhZdb3U0OKcZX2+8gB8eN
         mt/w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:date:subject:cc:to:from
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=QuII7OeV6TwzsOFJ0lZ2z+76+QSkx//ixRu4tomi5Fo=;
        b=bB/9Y81u1a+/yiLEdPeIvRfrpd/O52wx3FwuezlPOtFlv+kmiawCxZCJU8HSpDVlLi
         C8ymIbddth+RsCAJ7GT2Z0t8JxcMZ1ZVehoP0fattYPoJVowEZaodt6kMWoUnbaRPmuU
         BgafdVJAkcw4XSAMrQ5DgyMQ5g4+2aKdUvOlSjcSG06xJdoOFOv63keMeQIj6GHh7apD
         /kJvsmw+tb72d2rX3mEsop/MFxPBA/qgd3pFKP8w2IFUkHcB8pP7DuO/3w2OiSjMJC/2
         5jR/DOyV5YfzT4q3mNlrQDW5STfTyEFVU0N1xKkz29RSOkb27AM7KCa1I+1EKI9OHORM
         HwHw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf2fTdTSrMvs+Dr/iqNs6nBC7ATyrK+iaqo3bLxuLvuIDCfCoArV
	VTUIoxeCg5niaugwz0FAZKY=
X-Google-Smtp-Source: AMsMyM4moAohLbHtB1BTPcaiESUgTOGoOjDEIb3DgmqcBvqGeXhmqYNRbLj8DLo5hasNwdx+bNbt4A==
X-Received: by 2002:a5d:6648:0:b0:22e:43a6:fe0e with SMTP id f8-20020a5d6648000000b0022e43a6fe0emr2618943wrw.178.1665737394410;
        Fri, 14 Oct 2022 01:49:54 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:7701:0:b0:3c4:9c0:44ca with SMTP id t1-20020a1c7701000000b003c409c044cals2454436wmi.2.-pod-control-gmail;
 Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
X-Received: by 2002:a05:600c:2241:b0:3b4:88aa:dcba with SMTP id a1-20020a05600c224100b003b488aadcbamr2662354wmm.203.1665737393406;
        Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665737393; cv=none;
        d=google.com; s=arc-20160816;
        b=pULvn4xxymKlaTfONaq3lIXDPdn5hqerGxY6SgyJdScPjOpB1T8a879rhc3ZSZx5oe
         Bc1JIS/dDQ3qk9uKMBw5+q93ZyEpZ1cgsNs4a1aR2nVbJsmR898IPwP5J+iIR998uoUD
         6z8uAW3XLtMmI2pQkcSZ/wrTPkwtfnc1c1MhMT2Kj1golFeLyPcTYF+6ykCMxj3dcqnS
         GAVTm06lHbxFx5DKqtaL67vubwE6SrgACcspGdWNZf3AX4zS0uNtnQbm7se7x/2DGfCE
         5Ygot2doyVvFRXtA+56o5F9Grya1D2L41ozJ8LSZPRMCcNWVu65Xn1TgOGc7H6RExrnR
         6LWw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=uiJoxGZJlGz3xwdy8ebCPccYWzJULAWBypBIpnExuaw=;
        b=a5Uo0hXat8P1q9BBpX3prUL7lbBQkG8ssqG7u5hAnRuK5YTX4c1HnizxSt4+KUIVVU
         ob1afD0+EV/TYVAh7xguT7mBUjiIBD/95uew2+23lQmADrwe7p891X1p/u/PitU1UI0l
         1Ko5BKLql/4pD0zbORW4qleI+mmuejrFy4aJC8NlrxlaDJlSC7glC3Cnx4uGWXpCzwr/
         67TnEEBKGRuX3YKFx9ddQTHJ3RBCDj/H1cZRYM0T2I7xCV/Cv2Dzf+jm1wlpDFmXGnje
         r0z0Y2G1RiaRf1RYYv+TTCmzO1AdaDxbayCoQif5a8oC+tEJ88l8I5/YaxITb4rG7ktD
         SL0g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=aQXy8rp4;
       spf=pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wm1-x329.google.com (mail-wm1-x329.google.com. [2a00:1450:4864:20::329])
        by gmr-mx.google.com with ESMTPS id o12-20020a05600002cc00b0022a69378414si86255wry.0.2022.10.14.01.49.53
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
Received-SPF: pass (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::329 as permitted sender) client-ip=2a00:1450:4864:20::329;
Received: by mail-wm1-x329.google.com with SMTP id r8-20020a1c4408000000b003c47d5fd475so4907293wma.3
        for <kasan-dev@googlegroups.com>; Fri, 14 Oct 2022 01:49:53 -0700 (PDT)
X-Received: by 2002:a05:600c:3c8e:b0:3b4:d224:addf with SMTP id bg14-20020a05600c3c8e00b003b4d224addfmr9435669wmb.132.1665737392984;
        Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
Received: from hrutvik.c.googlers.com.com (120.142.205.35.bc.googleusercontent.com. [35.205.142.120])
        by smtp.gmail.com with ESMTPSA id 123-20020a1c1981000000b003c6c4639ac6sm1547372wmz.34.2022.10.14.01.49.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 14 Oct 2022 01:49:52 -0700 (PDT)
From: Hrutvik Kanabar <hrkanabar@gmail.com>
To: Hrutvik Kanabar <hrutvik@google.com>
Cc: Marco Elver <elver@google.com>,
	Aleksandr Nogikh <nogikh@google.com>,
	kasan-dev@googlegroups.com,
	Alexander Viro <viro@zeniv.linux.org.uk>,
	linux-fsdevel@vger.kernel.org,
	linux-kernel@vger.kernel.org,
	Theodore Ts'o <tytso@mit.edu>,
	Andreas Dilger <adilger.kernel@dilger.ca>,
	linux-ext4@vger.kernel.org,
	Chris Mason <clm@fb.com>,
	Josef Bacik <josef@toxicpanda.com>,
	David Sterba <dsterba@suse.com>,
	linux-btrfs@vger.kernel.org,
	Jaegeuk Kim <jaegeuk@kernel.org>,
	Chao Yu <chao@kernel.org>,
	linux-f2fs-devel@lists.sourceforge.net,
	"Darrick J . Wong" <djwong@kernel.org>,
	linux-xfs@vger.kernel.org,
	Namjae Jeon <linkinjeon@kernel.org>,
	Sungjong Seo <sj1557.seo@samsung.com>,
	Anton Altaparmakov <anton@tuxera.com>,
	linux-ntfs-dev@lists.sourceforge.net
Subject: [PATCH RFC 6/7] fs/ntfs: support `DISABLE_FS_CSUM_VERIFICATION` config option
Date: Fri, 14 Oct 2022 08:48:36 +0000
Message-Id: <20221014084837.1787196-7-hrkanabar@gmail.com>
X-Mailer: git-send-email 2.38.0.413.g74048e4d9e-goog
In-Reply-To: <20221014084837.1787196-1-hrkanabar@gmail.com>
References: <20221014084837.1787196-1-hrkanabar@gmail.com>
MIME-Version: 1.0
X-Original-Sender: HRKanabar@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=aQXy8rp4;       spf=pass
 (google.com: domain of hrkanabar@gmail.com designates 2a00:1450:4864:20::329
 as permitted sender) smtp.mailfrom=hrkanabar@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

From: Hrutvik Kanabar <hrutvik@google.com>

When `DISABLE_FS_CSUM_VERIFICATION` is enabled, bypass checksum
verification in `is_boot_sector_ntfs`.

Signed-off-by: Hrutvik Kanabar <hrutvik@google.com>
---
 fs/ntfs/super.c | 3 ++-
 1 file changed, 2 insertions(+), 1 deletion(-)

diff --git a/fs/ntfs/super.c b/fs/ntfs/super.c
index 001f4e053c85..428c65ce9a80 100644
--- a/fs/ntfs/super.c
+++ b/fs/ntfs/super.c
@@ -582,7 +582,8 @@ static bool is_boot_sector_ntfs(const struct super_block *sb,
 
 		for (i = 0, u = (le32*)b; u < (le32*)(&b->checksum); ++u)
 			i += le32_to_cpup(u);
-		if (le32_to_cpu(b->checksum) != i)
+		if (!IS_ENABLED(CONFIG_DISABLE_FS_CSUM_VERIFICATION) &&
+		    le32_to_cpu(b->checksum) != i)
 			ntfs_warning(sb, "Invalid boot sector checksum.");
 	}
 	/* Check OEMidentifier is "NTFS    " */
-- 
2.38.0.413.g74048e4d9e-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20221014084837.1787196-7-hrkanabar%40gmail.com.
