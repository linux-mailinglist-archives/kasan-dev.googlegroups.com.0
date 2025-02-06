Return-Path: <kasan-dev+bncBC7OBJGL2MHBB6HZSO6QMGQE2DUUAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53c.google.com (mail-ed1-x53c.google.com [IPv6:2a00:1450:4864:20::53c])
	by mail.lfdr.de (Postfix) with ESMTPS id 25D4BA2B05F
	for <lists+kasan-dev@lfdr.de>; Thu,  6 Feb 2025 19:18:35 +0100 (CET)
Received: by mail-ed1-x53c.google.com with SMTP id 4fb4d7f45d1cf-5dcd3f2f3d7sf1405195a12.0
        for <lists+kasan-dev@lfdr.de>; Thu, 06 Feb 2025 10:18:35 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1738865914; cv=pass;
        d=google.com; s=arc-20240605;
        b=PP7vujbPYS8XCxBRuhJzXc6Tf+CKwsI2IbYotpBSzHQvfzjl9fqbZ9YcqeXHGHgigb
         E6V2TzIGHZ9JqK7k+Ea0NqhDk+OODDPdzg4rBUJjO6wY/zsvAJcCpOO5TxcPgscEEBmx
         WbPBIWhg4GUJRqWSqt9qsTew0VIGU+KxMkGpp+8f5RuKsUZsfszZhOd8h3I8OZQ1jJ85
         K/gEDUoBG/nsdU5FCUnd18iYIPfys+sjVksn/E4wuUBo6Qv/cH2br5vbfDvRcP3hmBYZ
         xsWkpDQ7AgyNc1XT/xv7NZx7zrC9SAREDY0UebH6rCNAXR5gLEm1NfVFCSzodg0ub6TC
         /bCw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=Rcykeufy9zr4C3lieqfXyrJ2aTXBk9uBBwx1QTgN1VE=;
        fh=w4iKAdEyaqO2c+A6baKF1EMUy/ZGF9vURxN6fwb24ls=;
        b=RdVMTgAw98h+Lx+Xq5V1ZIobMa+ZT3sHM0Dx1mC5CtfrazQxOk32eTd1VttC166ObX
         cf784A2Az6ex3IL/Jq/HQyM4/T75fx4vgpAAG12N9/y0LzxFVOLjqW+2xHnkYWNRC+g6
         KwAV+VllS3fCQorE0WX2VeOFuXn15nKZjlwWXCNvuV3ld8HLpbC+Oph2oIylXakjh2Mm
         tGhhGcFlvn8E6oq+oFeLtWVFYUy2X3aXI1Fuak+2YB+oZrQUdOBi8Ua3yUZtYDm3BlxD
         hnDw3ZszRVeoTVrbUJEgmfZeb8y5tYyjVfGlouLqkG29jus6NZ1wGkbP1H7CxO5Ab0yd
         t/9g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ozcXtY7L;
       spf=pass (google.com: domain of 39pykzwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39PykZwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1738865914; x=1739470714; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=Rcykeufy9zr4C3lieqfXyrJ2aTXBk9uBBwx1QTgN1VE=;
        b=tRugYyqO/kWgD1VgPE4GtqS9T/bumOPrwb9+GMX5XdSZx4jwLWs2w8JOJ6hYyjHe4W
         lhv3X7lQRrvWotzMLeTu5qcjZBZ71GukO11P33s2/qSpmrBi2fdDpAzhm39dyRhrXUlf
         PuS0B4h+U+9c21JkifQg4GVTHYGKI3n6WCNTXfwb/LpnstT/QOb93lSR572zTq2yGRo6
         Xt4YJijd9Mbq4jebctHUXVHnPJLNhUQMCZuYageQlZo6uG9Zguzb8uAYGRwnO6cRM8JC
         G0Ve+hEoYh7mhI7dkToK6pzI86eLLaA2kkiSAk2fOzx/U2v8KKpsbHWvxi13zcpLQGQa
         V+/g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1738865914; x=1739470714;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=Rcykeufy9zr4C3lieqfXyrJ2aTXBk9uBBwx1QTgN1VE=;
        b=hLWnME/wve14WOh2NB5YPgEBzdi3YiH+L9RUqb4Bs7D44qgOlAozFn7gEemztTsUCj
         XokI3vb6U0JTsTbxf1wmsqzi4yNvY7OYI9CWRQOv6WMlNFTJ7sLQiIykNlcw3ZPhp9/v
         tNYbpLAUU6WdLjIIa2JEeUyehWohge0yRpxmMwXKGPQS0DFxjp+3Do6aT2+hR5/QLASa
         6VfHi8Te3G7W5+Xr3nk6vA718g5OH2CecXPXXUMkU42KWr3AUYmiqd8OmfsXTcpIzIS9
         VRcU1Z880FtsdE4WW6MKHQO8eif7EE52lXGrVPZmaJhT+vGIMQLdYj79R+VTnEE0hQ+B
         R13Q==
X-Forwarded-Encrypted: i=2; AJvYcCXpVdWWzPpvcDkIerOJInVwJJ1C1qt/USxgaiWGZ0GDxX6V/nP5EHwdWPPfKjykRf1uooq+lQ==@lfdr.de
X-Gm-Message-State: AOJu0YyDpsCau2ClxKEeQNlUICGtPAkzWUFQBJmKy7+fijYjs3HO6oN/
	n1Q61w2Z8QfNgGl6gJVHnbhONVhalrXxCQCV94SIIY0SoOCHQYoS
X-Google-Smtp-Source: AGHT+IH1wKx/hWH8f7PGXrQJDXZxwiBAdWXjGA6JUEr0V3G0TvUOWOXRT2XBdDcUicLPzYIhtRFNCw==
X-Received: by 2002:a05:6402:43cd:b0:5d0:8197:7ab3 with SMTP id 4fb4d7f45d1cf-5de44fe9d5bmr533867a12.3.1738865913252;
        Thu, 06 Feb 2025 10:18:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a50:d55c:0:b0:5dc:d09c:bd1e with SMTP id 4fb4d7f45d1cf-5de44e69465ls117205a12.1.-pod-prod-07-eu;
 Thu, 06 Feb 2025 10:18:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWd01o/Oz1w+tWJ+7NNQ0vhcbx9wvAt0a8zJwqgcCwtY3n+4frwguwow8KQn8b910WPt9Iaf7Fkelw=@googlegroups.com
X-Received: by 2002:a05:6402:4605:b0:5dc:1f35:563 with SMTP id 4fb4d7f45d1cf-5de44fe9ce7mr509806a12.7.1738865909307;
        Thu, 06 Feb 2025 10:18:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1738865909; cv=none;
        d=google.com; s=arc-20240605;
        b=G+QaIH0wQ2KCYPnxRV9eAvANZbE3Ynt6u6esl3ammyE0i4TfghQt75XREo2kNB15rF
         pXl49tmcjGAjavNmIPkh1gwNyM2OQtH4XfIgkyaPDlW5060mmh8zRHZZLuipX3yOW61d
         66b6jGr4OU5u1ZIz/6RrFndtFaTdOeEb0ZVcJjTLG16PqiCTjxTOM+EJzZY0HSzeGYgW
         l085ZxW4n5zqTbkyEQfUsXGlikX83GUXNIBW29OqavPHRKIsSFiuP/qco0Bbx9Huae3Y
         U0d2e0sGUsRqxE0+hyvFj0XsqtkxIcR8LBdE5LHENQlt1z2iNJBUrZ5CZQtSYiPBFzMq
         RYLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=rczBmZP1xxTJDBYPo5xjGBbOgXwfpsKdWxPKt0+mHDg=;
        fh=dHT1QwFsb7uTUNSgm4K38CUAjb9NxsbbhxcAHPTNzVc=;
        b=Ow/epwwnNicZUVxTD0knFPTqSKYCnj+Sn4NcDAklfc7pgEuMHtc6e2ebCIvjMPW1lU
         xkpwcHRQnXRl9x9zWdVHjE5kIJl8bboy7Y0UDYRUdQRXRCRwBUTOK2gAfv3WWQsFa0ZR
         F9dpFD/XLiDIX6CwGM5E3YbwcAD6eytZjHKKfkahuykiTCqcLLh/53uKhzW4eaiGie6+
         ATZtHufSssdsZeDdqskBC3v+ewxG9bv2H6sZOICAAQeUSnHS0/JCYH1sQo6pQa7pqjb1
         1yH9syEBLnyKK49xuMNB8B5y8xQpqi93vAeDCaFV2HDSdoC2O/jrm3L6mn6Km1sd1xgR
         8UsQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=ozcXtY7L;
       spf=pass (google.com: domain of 39pykzwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39PykZwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-ej1-x64a.google.com (mail-ej1-x64a.google.com. [2a00:1450:4864:20::64a])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-5dcf1b739ccsi43242a12.1.2025.02.06.10.18.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 06 Feb 2025 10:18:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 39pykzwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com designates 2a00:1450:4864:20::64a as permitted sender) client-ip=2a00:1450:4864:20::64a;
Received: by mail-ej1-x64a.google.com with SMTP id a640c23a62f3a-aa67fcbb549so132408766b.0
        for <kasan-dev@googlegroups.com>; Thu, 06 Feb 2025 10:18:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCXAYtSUn293YPoMDr9pNCpMsIKjAjsNoLEP3U9FAA4EEsJr3jNSKTsCDS/9wvmnqZOgD5E4yLfmo4U=@googlegroups.com
X-Received: from ejcth7.prod.google.com ([2002:a17:907:8e07:b0:ab6:c785:9cc6])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a17:907:7e92:b0:ab7:8520:e953
 with SMTP id a640c23a62f3a-ab78520ea84mr97837866b.55.1738865908835; Thu, 06
 Feb 2025 10:18:28 -0800 (PST)
Date: Thu,  6 Feb 2025 19:10:11 +0100
In-Reply-To: <20250206181711.1902989-1-elver@google.com>
Mime-Version: 1.0
References: <20250206181711.1902989-1-elver@google.com>
X-Mailer: git-send-email 2.48.1.502.g6dc24dfdaf-goog
Message-ID: <20250206181711.1902989-18-elver@google.com>
Subject: [PATCH RFC 17/24] kref: Add capability-analysis annotations
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
 header.i=@google.com header.s=20230601 header.b=ozcXtY7L;       spf=pass
 (google.com: domain of 39pykzwukccupw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::64a as permitted sender) smtp.mailfrom=39PykZwUKCcUpw6p2rzzrwp.nzxvl3ly-op6rzzrwpr2z503.nzx@flex--elver.bounces.google.com;
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

Mark functions that conditionally acquire the passed lock.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/kref.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/kref.h b/include/linux/kref.h
index 88e82ab1367c..c1bd26936f41 100644
--- a/include/linux/kref.h
+++ b/include/linux/kref.h
@@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
 static inline int kref_put_mutex(struct kref *kref,
 				 void (*release)(struct kref *kref),
 				 struct mutex *mutex)
+	__cond_acquires(1, mutex)
 {
 	if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
 		release(kref);
@@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
 static inline int kref_put_lock(struct kref *kref,
 				void (*release)(struct kref *kref),
 				spinlock_t *lock)
+	__cond_acquires(1, lock)
 {
 	if (refcount_dec_and_lock(&kref->refcount, lock)) {
 		release(kref);
-- 
2.48.1.502.g6dc24dfdaf-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250206181711.1902989-18-elver%40google.com.
