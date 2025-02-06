Return-Path: <kasan-dev+bncBC7OBJGL2MHBB77ZSO6QMGQELGFRAIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13b.google.com (mail-lf1-x13b.google.com [IPv6:2a00:1450:4864:20::13b])
	by mail.lfdr.de (Postfix) with ESMTPS id BE7C4A2B063
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:41 +0100 (CET)
Received: by mail-lf1-x13b.google.com with SMTP id 2adb3069b0e04-54411cbb2f5sf336023e87.1
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:41 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865921; cv=pass;
        d=google.com; s=arc-20240605;
        b=EiiqJUq1GIDMOOEnwaieSl+ZNexJy2QEhv3mIHt1h4YZGJK00BtQgJaVeBDENd9sJ0
         II6F2wiPVRvt8ZuCwqGC0IYjxCQjRtasPv1kFbN1CNcVrOIr3crhae9b2BntLv3qLqXM
         vJlrVEDsY+1G1os27rL605YXRnh7rrS4DZXhNAEHR5cdYsfPtrfvx27antaCTVFZ6fXu
         TtYRw18RjGYNzZgVVfZjNE3tKh8U/4KPC4eHmwnvgifs3sODYGLfY9T+zko5Z7KCOJjj
         jg4cvvKHjJXT1cnQG+QF8U0Ak8w7xWHlAIRGXaIiOIxmj2VvGnkl6pspX6nh1zuujGIu
         GXfw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=q7SOiP0AIhQUyI3hUUwa2PeYGMN/KtAzbX7D9cIj5fw=;
        fh=mtH+6GgF/wToIKcuMCfFB8JQNMHT/bRPOjxLczzbHnk=;
        b=gex9ynX8Vrc0hzAl2soQt1YCPWP90v2S5H/0bPd6NexTqV5tn+ZUiqURLTeiDN21F4
         noM7t9I/bL3Xd1iPGJaCEuD7CI63d7dTWgFvfdK9j6+3a95Le4YMAg0CPH0g0rbqJghj
         QK5k94BqNLhdZ3SdgHnyKdm7xT+YnYWYT64O/K9t66XclTOpu0Q/4MkuvKoWJii0nLDA
         WDWMmeeN6w/RdoMbCTbOCYq2G517M8ZndPGXcDBG4q/6JgUxdxd9OlVcALSpaDl9kOcq
         Y3jgN5sXYJI0rP1VoDPlsVJA/d8ysJQ4WKsqKsyrqb7mLue0bOAFpZIo+EYmB6+SVkQr
         n/ng==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q1RzrwtA;
       spf=pass (google.com: domain of 3_pykzwukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_PykZwUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865921; x=1739470721; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=q7SOiP0AIhQUyI3hUUwa2PeYGMN/KtAzbX7D9cIj5fw=;
        b=YvQ1APV/zQR2a4pnh+sm8VB8FBKEJEj2YTgLodPsR2+eS8zcRLnuppJFIn4p02RX97
         UlmF69ql3dmIoxLzf/gE7SO1Fmymd8HPkUceh2/0a0sFnIvi1VNSeIopnTpOjvNFILw8
         Euc1COkFCA1GjdqKrBGjqMYBmoAiWmeeQGSnO0NGqeVTT2MECfcK8Sq3DVLGg49cDpMS
         f6ksjgC66pXgEb2p+14/oPs2+tjoA6QfDPbPYOADqn+TiaDBsuweYltAo9d+hDvWDRN7
         665mX1QdrbdvcM9pv9ymhzVsRgQI1fuayUFD6HmkimdYhqbIdnkpDY1zLL8u2H3N8os6
         VZcw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865921; x=1739470721;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=q7SOiP0AIhQUyI3hUUwa2PeYGMN/KtAzbX7D9cIj5fw=;
        b=mOZDtBKUOH9gvRCKRX9OVKS6yIPo5auWHxPFwGmKhBQZUMZEyXC9DtwBqyA+9IRSh6
         zZDWXx5EzUQjZcrBIPzU3XFgnvVsaL95ZDY2Oo/gr/dmFNlYyiea34t+lAT5v6ZFkLk/
         PjPOSyPD2SkHG6oEhNPdgYyuT+G6LP43zvIEAnCB433ftetKdliuDVbtryf0AqBqe8Dh
         LoGPW5CPiwsigOxnSOYajlCNbSr+ozLYu3NFRGntyaLQTgBLYeEraN3edaxlkDUb9Xmo
         M5w4gQadbiVrEtcQ1swUFXMpMWosuwbi6+huJjyBPhR5RnbvT5YE/cZvT0lVZIVdSTAY
         rBWw==
X-Forwarded-Encrypted: i=2; AJvYcCUyd3GrTUEpgYA9lGra1nWdtl+YVtDr/wsPqdMPtdAeh4J8aAt5zHfr9d2PkkBGGKvy01qpxQ==@lfdr.de
X-Gm-Message-State: AOJu0Yzywr6a7hV1edup0pl2LLIeqTcqUj8geovzLf4L6ezEx+VaFBuY
	qKTAwWa0HD3yZQCw5R1YxvZ0h35W+WFJTs/PQfqAW9JGetro0Y6y
X-Google-Smtp-Source: AGHT+IF0klq7goRmCEUe8xPTqK/DArBpxvk+qogFoqMxsE6u7P589/nJR8b/o9uWuFWpxaTdV7z4Iw==
X-Received: by 2002:a05:6512:3f20:b0:542:2e04:edc5 with SMTP id 2adb3069b0e04-5440597ea87mr3010606e87.0.1738865919682;
        Thu, 06 Feb 2025 10:18:39 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a19:2d02:0:b0:540:165f:aa5f with SMTP id 2adb3069b0e04-544142af626ls6542e87.1.-pod-prod-02-eu;
 Thu, 06 Feb 2025 10:18:37 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCW1jnUsLhvlvEmDwvfXWpnl4w1Fy2MeYbCTBCMtOk5y/7lumBGY6HgJzop40xHkZdJFMiBfa0ALBrI=@googlegroups.com
X-Received: by 2002:a05:6512:31c1:b0:540:1fd9:b634 with SMTP id 2adb3069b0e04-54405a4245dmr3314818e87.34.1738865917006;
        Thu, 06 Feb 2025 10:18:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865916; cv=none;
        d=google.com; s=arc-20240605;
        b=BcYzHklHCuYxT9cYvqGDhSF6T3eWwFdmMghczgqhtcarB7eHGJWOCY42xnBIM4qSBW
         Ln9gLKyXeOSCSXLh8ALwRfYXhfCDoY1mJBXX6uqJLwQJgOnHV0xZon++DmzS2nbcN9EN
         v5S6+nNp6kFr/BBwny8CYs/hleHbCmb2cRcyZiY1AizoFQ6r4HDOcY6T88R48Q8a/5Cc
         ssw9LljDOC8t50AdkP4svSyFhe6I4kUiX30fyJqg/3X+0OH2+wtUiZOV/EDw8TizbzXL
         YGL6JP7+a13aQ+tCKYoETtBBSkEHNH2w/3yPCv4skPv0acovgsHefX5ZzQoxhs56rJSa
         Etkw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=Gbrljv8lkIJmai+iapf5Yd4+selXZvjO0vfpPpqYqbM=;
        fh=o2tJvWGdjmWOxEHvLyOlm6u06/PJL2tlPtLzuu2u4n8=;
        b=T7uJHNHgyAM/rWSqj1b9ABbroYip5n+T8Y57zDX1kw3oV6WHCmsq9P9Yf6nlbdx+6n
         lr/7NKs9kKQccks78hP2fM+nvOWFxo9+o7PkkqhsdJgXFcQBOJ+4ZkqWW1+AoGZ+t3Q0
         tqnq5evtfvMfX/p8cZ/IFvi0snpLrh+2Xqa+vJTQ77sUVF+Sufb/0Se9kyM6gqktiBxl
         cVP6W6qj1PxDnK3q0zC+GqKfgITwa2jy0UdzNa7UpkJh1MnLqg3lgWoHRF6YR9OR9kNY
         kqfuOamMXvxFtNKM+C8rd6alhVVyNqcecZUdwlnk3Pt/UUREtVJgrP6xDcCAjCT1NTWK
         mEwQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=q1RzrwtA;
       spf=pass (google.com: domain of 3_pykzwukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_PykZwUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-307de2215c2si381041fa.8.2025.02.06.10.18.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:36 -0800 (PST)
Received-SPF: pass (google.com: domain of 3_pykzwukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-aa689b88293so130834266b.3
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:36 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXxUmm1McTTSqy4OzuDSSLKbAXxXbSClf2HjebeGQklqUyIbKThf4BHIz74Pov+wlRBFtC2fjB4UPI=@googlegroups.com
X-Received: from ejcvq6.prod.google.com ([2002:a17:907:a4c6:b0:aa6:bd80:4523])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:6d1e:b0:ab2:f8e9:723c
 with SMTP id a640c23a62f3a-ab75e210266mr866257866b.5.1738865916587; Thu, 06
 Feb 2025 10:18:36 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:14 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-21-elver@google.com>
Subject: [PATCH RFC 20/24] debugfs: Make debugfs_cancellation a capability struct
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com
Cc: "Paul E. McKenney" <paulmck@kernel.org>, Alexander Potapenko <glider@google.com>, 
	Bart Van Assche <bvanassche@acm.org>, Bill Wendling <morbo@google.com>, Boqun Feng <boqun.feng@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Frederic Weisbecker <frederic@kernel.org>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Ingo Molnar <mingo@kernel.org>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joel@joelfernandes.org>, 
	Jonathan Corbet <corbet@lwn.net>, Josh Triplett <josh@joshtriplett.org>, 
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, 
	Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>, 
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, Nick Desaulniers <ndesaulniers@google.com>, 
	Peter Zijlstra <peterz@infradead.org>, Steven Rostedt <rostedt@goodmis.org>, 
	Thomas Gleixner <tglx@linutronix.de>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	Will Deacon <will@kernel.org>, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, 
	llvm@lists.linux.dev, rcu@vger.kernel.org, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=q1RzrwtA;       spf=pass
 (google.com: domain of 3_pykzwukcc0x4exaz77z4x.v753tbt6-wxez77z4xza7d8b.v75@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=3_PykZwUKCc0x4ExAz77z4x.v753tBt6-wxEz77z4xzA7D8B.v75@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
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

When compiling include/linux/debugfs.h with CAPABILITY_ANALYSIS enabled,
we can see this error:

./include/linux/debugfs.h:239:17: error: use of undeclared identifier 'cancellation'
  239 | void __acquires(cancellation)

Move the __acquires(..) attribute after the declaration, so that the
compiler can see the cancellation function argument, as well as making
struct debugfs_cancellation a real capability to benefit from Clang's
capability analysis.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/debugfs.h | 12 +++++-------
 1 file changed, 5 insertions(+), 7 deletions(-)

diff --git a/include/linux/debugfs.h b/include/linux/debugfs.h
index fa2568b4380d..c6a429381887 100644
--- a/include/linux/debugfs.h
+++ b/include/linux/debugfs.h
@@ -240,18 +240,16 @@ ssize_t debugfs_read_file_str(struct file *file, char __user *user_buf,
  * @cancel: callback to call
  * @cancel_data: extra data for the callback to call
  */
-struct debugfs_cancellation {
+struct_with_capability(debugfs_cancellation) {
 	struct list_head list;
 	void (*cancel)(struct dentry *, void *);
 	void *cancel_data;
 };
 
-void __acquires(cancellation)
-debugfs_enter_cancellation(struct file *file,
-			   struct debugfs_cancellation *cancellation);
-void __releases(cancellation)
-debugfs_leave_cancellation(struct file *file,
-			   struct debugfs_cancellation *cancellation);
+void debugfs_enter_cancellation(struct file *file,
+				struct debugfs_cancellation *cancellation) __acquires(cancellation);
+void debugfs_leave_cancellation(struct file *file,
+				struct debugfs_cancellation *cancellation) __releases(cancellation);
 
 #else
 
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-21-elver%40google.com.
