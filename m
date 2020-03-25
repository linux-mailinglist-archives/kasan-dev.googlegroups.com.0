Return-Path: <kasan-dev+bncBC7OBJGL2MHBBZUT53ZQKGQEWD6KUPQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x140.google.com (mail-lf1-x140.google.com [IPv6:2a00:1450:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 27F02192E71
	for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 17:42:15 +0100 (CET)
Received: by mail-lf1-x140.google.com with SMTP id j13sf1054258lfg.19
        for <lists+kasan-dev@lfdr.de>; Wed, 25 Mar 2020 09:42:15 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1585154534; cv=pass;
        d=google.com; s=arc-20160816;
        b=z26TdX2WRY86gxWO7Bn0xqeDq1A2AcSQqyI9n7E6aCXmnoovViAuvH6VDKyqYxNaLH
         KTUwwNX50nEy/r6xzFM6BDNNMwbzQ+f7KEKdFkXosKS7Qu8icDEjnlll3bu4FuUjIzDm
         5Gj+/vDfNasajg/0drmlL3SfGCt3ATzU6fejrA2W7WP0rLutqvi9m67tjFrmBUrLq5Nx
         1jivgUXkjQ5MqRDvu2GrtetuYmimWTXVPjOit/K+kzrAITVb4ywfOyNYYlT0d/QnhXs3
         OFecdZWshLwdq0boddrUt7os0zyGuHTcclhAn6GuearfXJKgut1lZgS/kUIwVBlJTG9G
         7Zgw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=J3YvD4a/REMKfti1WEFB6Z1AE4Rbwv3j3ajf9gUbqeY=;
        b=vikOalqY7Xw/TmRJmjG6yKUTiHI4AKrZtyYFRCpwqRkekt70ndtx8acNpxc81u3y8m
         MTBiGz6xAkfO+9gOkwfj+N8eGMR/bfF97d9N5/rtUlqOKXS1wBjJcIVow7jL3bGOo36m
         VFc5JC4qfKeUbHCJl3D9IIFiSGuxERN6PSpfw673htkNaLSKOl03gP8sw7fhYjj/lBtu
         upJfaIfAGhscvmTeHD7IxgPbwbgZWqmrWHmQ/0r0adcYiUY+ayOGSS4/nzvhpksZGWeN
         87cmkXMg30vNeAyJgG5HGO5GBFsVj9RPlPh+IJbXV7soGZWcusTN/4KXpIKxraX5tI1y
         5u2g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SraYyH3S;
       spf=pass (google.com: domain of 35il7xgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35Il7XgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3YvD4a/REMKfti1WEFB6Z1AE4Rbwv3j3ajf9gUbqeY=;
        b=DyiPaZaeagO8qHK5tO+5X2lgNUz6YbOJtZisKxgweItjYryc7iUQ4jsNrfnh9zP6k7
         12SDImE+ao2f6MNKOvIUDwb2P2lPbP4EmzyFVJ/KivIGCbiWLYSi/0K2G6liSQ+WAef9
         litQO1mhR1D8s+2DAnDV1e92/iI7+WVi5S3omJ9W1ZJZsI1tsjZ/bcg2AuPZ4xkOG7NI
         dPOFNWd8A1HCZrqpHTQryFh5NcOrG0ZkNkawSvyYk4gOAH7uLfU94cFwZ/63PPwL+Djx
         QBKiIBACX9lZiQVvzAYvopBKe/cycNxmkoAx1FmgW6ypl/VfhcKFcS0jsCyXJwA4tKr2
         2zTA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=J3YvD4a/REMKfti1WEFB6Z1AE4Rbwv3j3ajf9gUbqeY=;
        b=eXrsyRT0nLQ40dDM2GVHTNXDDCfYzUKVbkoP7bIebWLP6giSEzhBQC4wxWFknF9QGp
         V1rSMCN1il2+6d7dzF+tTyXczFDliccERPMSVzp3jomQT/i9VcwFz0rk1mOC2JLI7CiX
         a3xhWNLRzp+7g3MQ9RiQQJC8Er3tJD/OROeI6DiFT+kxF1yDxjTW4f/Lykr0dusnS1Ly
         kf+KUsHsHfwmTy08ExOkQTBxOyn3ULnts/eZsHSxdodAY/R5eLTbXQFEt4TuehDREqPo
         es57frdOBnQ2mlUPJNsGnJCQSgCm6l9FjQRus/w1ywd6l44kqWHM8Cr2pwG2HB9RX7Cx
         jsZw==
X-Gm-Message-State: ANhLgQ343GWlB5dE18NKjCmImjkC9eKnJJaCg37iLpiezhNV1FUoL18T
	N++URb72DuIv5EVcTccDN8g=
X-Google-Smtp-Source: ADFU+vsvw3QA2TIPfYm00As6Pt++y3U8cN+V+kWPKlxz/VuqpzAAh1L7TqZZFbWWO7rQokHffat1gA==
X-Received: by 2002:a05:6512:10c4:: with SMTP id k4mr2867357lfg.98.1585154534523;
        Wed, 25 Mar 2020 09:42:14 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:686:: with SMTP id t6ls380832lfe.3.gmail; Wed, 25
 Mar 2020 09:42:13 -0700 (PDT)
X-Received: by 2002:a05:6512:51c:: with SMTP id o28mr2912363lfb.116.1585154533622;
        Wed, 25 Mar 2020 09:42:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1585154533; cv=none;
        d=google.com; s=arc-20160816;
        b=nQJ6MkjOJm4hmzybpjAojK9vUMaj/s1AWA5ynxmOr7BFcsxVRgzNlU4vGOvcsK9oD7
         yIdPNqbxexhUvJStYeZNjfcTOGc9pGWGbWaehLs3DftmtclmyweGmOr7wu+I1WJVWzqz
         B0fsecPf5f3IIgf/39ULuJ0LkUB+7c2vLZ1pnzChC9azN1KNroL4b/wsoP29Y8jWadAH
         /DvZ40fWmi27uLOjsBpRgb7fN6Zj7lPtj5A6Ds+dV1MqZCS1S3Kw7Il3SCzWabQEy7/S
         sH1NmVLIOTNsWNtHBJX3C3KM02q8M9whnlRg/mNvvBOQDolycmTIMmK+fYxtJvjpFCN6
         Wm1Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=PkTGLT0FCPWQdDVWIHBabhnbaBwpL2cH8uoEASC76jo=;
        b=vziZSWK0SzWAlpnnX9sJ9zbQKYB1zxUHa/etAGRFFf3JBc4gHej4So7BoPKeayLTHc
         nyQPUFxJWCwcAJPO9pSJjAtILIWtX4tcN1tV5NSghPiWLrJwqbyPvall5cw2nTrQUatn
         1hNR4bl9OrvefiRMyxcv0TC6WEDNbLUZDXL8RoseeBqVSmakHLvtPJYwSQAdhwLAgOZx
         eLS5eHAs95YX4qvLr399zihD9QcXHUPnVAQjqskXtcCA/yzzrgO8alreH2P43eMd38PI
         3HuwUrpKG6FRQV3yuu4b5q6Q820dTRo54HQYu6H3aFNvtg7ia3qN6C/AtrpyT5wToRtP
         cpcA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=SraYyH3S;
       spf=pass (google.com: domain of 35il7xgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35Il7XgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x449.google.com (mail-wr1-x449.google.com. [2a00:1450:4864:20::449])
        by gmr-mx.google.com with ESMTPS id p5si175201ljj.3.2020.03.25.09.42.13
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 25 Mar 2020 09:42:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of 35il7xgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::449 as permitted sender) client-ip=2a00:1450:4864:20::449;
Received: by mail-wr1-x449.google.com with SMTP id u18so1392588wrn.11
        for <kasan-dev@googlegroups.com>; Wed, 25 Mar 2020 09:42:13 -0700 (PDT)
X-Received: by 2002:adf:9b96:: with SMTP id d22mr4630726wrc.249.1585154532828;
 Wed, 25 Mar 2020 09:42:12 -0700 (PDT)
Date: Wed, 25 Mar 2020 17:41:57 +0100
In-Reply-To: <20200325164158.195303-1-elver@google.com>
Message-Id: <20200325164158.195303-2-elver@google.com>
Mime-Version: 1.0
References: <20200325164158.195303-1-elver@google.com>
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [PATCH 2/3] objtool, kcsan: Add explicit check functions to uaccess whitelist
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: paulmck@kernel.org, dvyukov@google.com, glider@google.com, 
	andreyknvl@google.com, cai@lca.pw, kasan-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=SraYyH3S;       spf=pass
 (google.com: domain of 35il7xgukcd8fmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::449 as permitted sender) smtp.mailfrom=35Il7XgUKCd8FMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

Add explicitly invoked KCSAN check functions to objtool uaccess
whitelist. This is needed, to permit calling into
kcsan_check_scoped_accesses() from the fast-path, which in turn calls
__kcsan_check_access().  __kcsan_check_access() is the generic variant
of the already whitelisted specializations __tsan_{read,write}N.

Signed-off-by: Marco Elver <elver@google.com>
---
 tools/objtool/check.c | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/tools/objtool/check.c b/tools/objtool/check.c
index b6da413bcbd6..b6a573d56f2e 100644
--- a/tools/objtool/check.c
+++ b/tools/objtool/check.c
@@ -468,8 +468,10 @@ static const char *uaccess_safe_builtin[] = {
 	"__asan_report_store8_noabort",
 	"__asan_report_store16_noabort",
 	/* KCSAN */
+	"__kcsan_check_access",
 	"kcsan_found_watchpoint",
 	"kcsan_setup_watchpoint",
+	"kcsan_check_scoped_accesses",
 	/* KCSAN/TSAN */
 	"__tsan_func_entry",
 	"__tsan_func_exit",
-- 
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200325164158.195303-2-elver%40google.com.
