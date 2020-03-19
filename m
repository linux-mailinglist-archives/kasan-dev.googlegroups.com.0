Return-Path: <kasan-dev+bncBDK3TPOVRULBBBGCZ3ZQKGQEM7GU27Y@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-vk1-xa3f.google.com (mail-vk1-xa3f.google.com [IPv6:2607:f8b0:4864:20::a3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 226AA18BCE2
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 17:42:46 +0100 (CET)
Received: by mail-vk1-xa3f.google.com with SMTP id 133sf1016129vku.16
        for <lists+kasan-dev@lfdr.de>; Thu, 19 Mar 2020 09:42:46 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1584636165; cv=pass;
        d=google.com; s=arc-20160816;
        b=gGbt+VqKtKy5HGam8gzxKqS2Y27NLTJNtC8TPuj1OvTLbJOa/ub30jiLg8Nk23gReK
         D9EpanEPzEXEhgUrrPTnBR5D15G8oCUHqJCnOXhAtT5GuZqsBzI/uXEFmKreVklCk8Ic
         HMnuoLwT7bFp2q77T8+M0mmqH/2iSM1XbPb5w9ce8s4WUhJJtqqN+PyT76NKBLFNlB7D
         0tzRK3dL3/mHE2ubdFxKu8ZsZVrCjqE8aBOgvY5N9G2BtaoVSeK076BKPA5urQbmltOo
         i5Kvec8El1FsQN4O6+rUmpyUGh8KCCDhH1/f3zTlSpehVycbfO8UM+oLpsdoLPBVtcSq
         IY/w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :references:mime-version:message-id:in-reply-to:date:dkim-signature;
        bh=oKkPeq9w8/aH6eyd6o3MCL5sxuwu1p74gUpylSV/Ub0=;
        b=lKjaxU94PwVCt/Gbh7H5q2pekJcufZFe1bnmTYP/T5kqioc8SekI80ZEqQJVk+0wmx
         fTjYSTBuLl466YgqxqrmmJW8pE7jk8VCEJGP8Vm/Rta6a04VbZfzO+YiFxRO6rcbQ/4w
         VF++3x0VdmvS60Sb12AgMmOjYOI0xPDWoUq+F/GGzPfoQc4qNT3Wq6x3FXC38JsYsrVc
         v8cYzBwcbxT4FLBASn8ynvNQgqKG0nzCtfcXw7LJ4NCzJRBJW9HIBH8OA7ZybgdlrlUP
         2nO5LR6c/AbvzENCZOgUjGtr/CcUrKepQKfxRrreJBEjlDhaXKMF5V3yzPL5JK5bRdrn
         NVhg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAEEZ2fM;
       spf=pass (google.com: domain of 3bkfzxgwkcq886x7wp0u3273v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BKFzXgwKCQ886x7wp0u3273v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=date:in-reply-to:message-id:mime-version:references:subject:from:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oKkPeq9w8/aH6eyd6o3MCL5sxuwu1p74gUpylSV/Ub0=;
        b=ODwE9z7HkgLOst6eNyLEGd+h8xHBktUy774k0BUU/EYJmQMyfUIXHVHvp4KVIldLFc
         JnYzGxqZePvQ8GYOamZ3j9BOCDELQxSmkzrfwDwMB54Rec41LDE3ArBYGp/4AbVvzR/p
         s57OuAyp4W4LYmE+XpRo6RAoUmLGInRt5WkIJPwAJHUcNRQgZKDlYr0zeMhZUHveMV6R
         H590I2aDBwpTqI0NDaO+TEIko7eXTti9xvl3F3Kc6HevSPfIxHGcgF/AVVuA3IoZl5n1
         gZvofXfv8r1kkbnMQCfaS8R4133t1U6sE4yeAJvd0avtBYadctApiVprU6qwRBwWVzDd
         r8CA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:date:in-reply-to:message-id:mime-version
         :references:subject:from:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=oKkPeq9w8/aH6eyd6o3MCL5sxuwu1p74gUpylSV/Ub0=;
        b=G5ydWXw4zKYauhg6sZKZTObfHAVuIVkhSWYWyb8BGIUQjm2Dv3Mq5Tu1v1nVUI4gJx
         xNqn/qFXQSDjd5NU4fJ79YETcFwoG0B5GfSt4Gq8H4gnRxLUKQQ3mnr10o5Cu1+ORnjH
         YQ6uWQOhek3zB8oUZ5W3KY9wOpNIsujGz++sZupWkEE7pd5TnH72LodaicbxbWHdGyJj
         tbpszl8r0M91fzaA62jSmdlZ4053Sixj8rKyf5nV+H47kw2chtepafdT2JyQ4mOVOcsJ
         +ImM5phj3Wmfe6M0ShY9yyjEaC0WbdxZ40F9cIBmcHad3iFjtTT+rdXkmk5Ydrg6tlFk
         1+ig==
X-Gm-Message-State: ANhLgQ17PvatiVqH0w7rMtMh1y7OIuCalC1nZegGq0CIwBbAX8ok2NJK
	DdFTLr+wJt23k71Kasyb1Ts=
X-Google-Smtp-Source: ADFU+vvuMxrDRwPE4H+aPxblVptrCtxbpjJFCa0GV3NyEJI52wBkCFJUiT6XIJ4BTlWc9ZW0LwbV/A==
X-Received: by 2002:a67:ef52:: with SMTP id k18mr2784208vsr.67.1584636165025;
        Thu, 19 Mar 2020 09:42:45 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6102:22e8:: with SMTP id b8ls450956vsh.0.gmail; Thu, 19
 Mar 2020 09:42:44 -0700 (PDT)
X-Received: by 2002:a67:c497:: with SMTP id d23mr2883211vsk.139.1584636164563;
        Thu, 19 Mar 2020 09:42:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1584636164; cv=none;
        d=google.com; s=arc-20160816;
        b=LMuylTygeYH3KXS1pCy7QrnwmO1QfCuoJ0FaB/i9l8cW/uVRtwaDae7Bu9hILa/Vbd
         C2ASJZmkVCmGv0jv7ghhW+rjANaAfUAsFsR6sYJ04Jhl5Z1Rm8uiZmZPTf7Xkg/cMnEg
         SHIrHZC4EVJVLi3wPTZ0lTuFloK46LFL0VimSfGEHdAUSMQuFvHNX6aPimCbIlJ4x/cF
         ML98TMHC62Y5baB4o0fFlbA+0VS2+iUzVIg39dWlw4wbZCYKZmaxirjicSvHpJ65yeJb
         /P3huHdQC6s8uCf5SN1MLk8XQ2SuckOrZkWllU8ScGPXG8OF4LomEvcec79Iv7I1CkPE
         miPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:from:subject:references:mime-version:message-id:in-reply-to
         :date:dkim-signature;
        bh=/e3rkkmfd1b6sk0SVgpVxi2weXIopunVz1TGXPB1o2Q=;
        b=NM/POq3TfrXNu6FcHFrnGxKFIfyO4WcuYj1fywG7pkUir+eB3r2WRYXWkRiUWIYsXQ
         PrqE7ZOXWiBzotv4WzPEkORp3py28wjgQm3J4l+4pLPmkI/8dQN7YKOLAH6QjvAwHS9s
         cLUgseN2UA6UFaAOTaqGp70FnKrH/Y5KMwEV7jMZMmDJ1wsu7YiaNcUqZ34ooilu2/mW
         NQ4z/8ZEoIyiIjfzWsbMfes3JhSzv1IKgQjySU6OkByhkvm2B0NmjFLyQil4CH6L78fF
         5ALGF8yq1LF0+McWod4tYiE3WDr2JgGhVswmwJs9gfJEdPGJyAuus80lJPzDd2IRhJ/g
         Qu6g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=pAEEZ2fM;
       spf=pass (google.com: domain of 3bkfzxgwkcq886x7wp0u3273v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BKFzXgwKCQ886x7wp0u3273v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x74a.google.com (mail-qk1-x74a.google.com. [2607:f8b0:4864:20::74a])
        by gmr-mx.google.com with ESMTPS id c9si98565vsq.2.2020.03.19.09.42.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 19 Mar 2020 09:42:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3bkfzxgwkcq886x7wp0u3273v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--trishalfonso.bounces.google.com designates 2607:f8b0:4864:20::74a as permitted sender) client-ip=2607:f8b0:4864:20::74a;
Received: by mail-qk1-x74a.google.com with SMTP id a21so2982446qkg.6
        for <kasan-dev@googlegroups.com>; Thu, 19 Mar 2020 09:42:44 -0700 (PDT)
X-Received: by 2002:a0c:edcf:: with SMTP id i15mr3610736qvr.151.1584636164003;
 Thu, 19 Mar 2020 09:42:44 -0700 (PDT)
Date: Thu, 19 Mar 2020 09:42:25 -0700
In-Reply-To: <20200319164227.87419-1-trishalfonso@google.com>
Message-Id: <20200319164227.87419-2-trishalfonso@google.com>
Mime-Version: 1.0
References: <20200319164227.87419-1-trishalfonso@google.com>
X-Mailer: git-send-email 2.25.1.696.g5e7596f4ac-goog
Subject: [RFC PATCH v2 1/3] Add KUnit Struct to Current Task
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
To: davidgow@google.com, brendanhiggins@google.com, aryabinin@virtuozzo.com, 
	dvyukov@google.com, mingo@redhat.com, peterz@infradead.org, 
	juri.lelli@redhat.com, vincent.guittot@linaro.org
Cc: linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, 
	kunit-dev@googlegroups.com, linux-kselftest@vger.kernel.org, 
	Patricia Alfonso <trishalfonso@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=pAEEZ2fM;       spf=pass
 (google.com: domain of 3bkfzxgwkcq886x7wp0u3273v33v0t.r31zp7p2-stav33v0tv63947.r31@flex--trishalfonso.bounces.google.com
 designates 2607:f8b0:4864:20::74a as permitted sender) smtp.mailfrom=3BKFzXgwKCQ886x7wp0u3273v33v0t.r31zp7p2-stAv33v0tv63947.r31@flex--trishalfonso.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

In order to integrate debugging tools like KASAN into the KUnit
framework, add KUnit struct to the current task to keep track of the
current KUnit test.

Signed-off-by: Patricia Alfonso <trishalfonso@google.com>
---
 include/linux/sched.h | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/include/linux/sched.h b/include/linux/sched.h
index 04278493bf15..1fbfa0634776 100644
--- a/include/linux/sched.h
+++ b/include/linux/sched.h
@@ -1180,6 +1180,10 @@ struct task_struct {
 	unsigned int			kasan_depth;
 #endif
 
+#if IS_BUILTIN(CONFIG_KUNIT)
+	struct kunit			*kunit_test;
+#endif /* IS_BUILTIN(CONFIG_KUNIT) */
+
 #ifdef CONFIG_FUNCTION_GRAPH_TRACER
 	/* Index of current stored address in ret_stack: */
 	int				curr_ret_stack;
-- 
2.25.1.696.g5e7596f4ac-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200319164227.87419-2-trishalfonso%40google.com.
