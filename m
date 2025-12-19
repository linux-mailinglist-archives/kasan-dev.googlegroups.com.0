Return-Path: <kasan-dev+bncBC7OBJGL2MHBBV7GSXFAMGQEFMXXL3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23e.google.com (mail-lj1-x23e.google.com [IPv6:2a00:1450:4864:20::23e])
	by mail.lfdr.de (Postfix) with ESMTPS id D4037CD096E
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:32 +0100 (CET)
Received: by mail-lj1-x23e.google.com with SMTP id 38308e7fff4ca-37fe633e654sf13094601fa.2
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159192; cv=pass;
        d=google.com; s=arc-20240605;
        b=ek/4h2vYXx22Kc3Ukei5Gm+gQ4xvB5YqHswP/BN8EpcP5wu3fZ7bnZ/XNqzdsOmj1P
         NW7DO/lzOTykZmZgr68WeY0ly47EXwT3IzHSG0Gh7PHDClsLaK1c3GMo0hebdkfM00n7
         JmP5kWRdECLDjE7Xm7vaUubVgDyVgRPDXY8wqhEcmfdr2VCq2DkolX/OhqL8AxBgx7fz
         ncc8K0qvvimERykKJKviIQdNvxfLh60/JPAGfwbO2KNqmFgSbHS9Xkrcg8icXw0Fiulv
         Iz8IyXbhKUpcmPlYcSBLWiP5bUQe8ZMeoKHWgP5qyPE0jAG+E6TlIBGnPLaIbvnHDX77
         M5TQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=G1hbAnyq32MyZfg9872aAPcwaAft0FW7EgBiXrMfXr8=;
        fh=2JvhNxU0Gmdwf2cikGJ5vnaQ/V6YDudH6m+o2vqlopA=;
        b=bgeOQgGZeo4VWlDYLSCmU6i58eZNICfvs4C57TYJrbCBYOnQ+n8xPhWNuuI1YOOxde
         ufN7iMr35w3mg9eCiQdm0ZQHEiFlta6ZZ6yRhPiiFIhAxQfGBokUG91fs80MA7hIg0SF
         jQ7kM64g+FHYq0HKoH3o9K5x0UYBXR7p/Oqu8l7sFt+dLPWL3vMcapj9gURzuiDmyLGy
         lsFFr1z5++iyX4f+kknxziUXqbwdjuzENT/lHBL8nzDKBKUmqFw5fDP1x1YNnUDoNcLW
         mU4BZ9Dcg395SwfyuDm8+xNIFWuke1MNsy4RuYUZsnXjGYfdesAxmTJmTWEg3hqn5hPB
         8uNw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BLOC63QA;
       spf=pass (google.com: domain of 3vhnfaqukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3VHNFaQUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159192; x=1766763992; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=G1hbAnyq32MyZfg9872aAPcwaAft0FW7EgBiXrMfXr8=;
        b=TBPxH8Dlgp38pX1cJ3+5/2Z0GD2efEmcdunzGeEP7Yo161omP5OvOIHZLH+nes2vIR
         fa9r8LNv5EIFZI+ZB9bGG4+9RSmW2b2tblR0UByiLBp1M3evj9VClGuvB0mi3VVKllRI
         i2s55zwvujhTDKWjIMLJ2hWP+GmIzq6DMe/UmkjsVayYHFPky10RfYaNYDTT8vCsRuM8
         PVCqC/YzjJqv/MlfxJcDY0Sn595aGo8+mvSgnqCuOpKFLdqCn0Au8maZMNYWSDKwYszs
         Zne4OwTV3yauv/H/rL4D4o/1qXELJDB7gzdzUBYxRaLX69CtKzOBsG7AjWIgoFQ4f6Rb
         H3mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159192; x=1766763992;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=G1hbAnyq32MyZfg9872aAPcwaAft0FW7EgBiXrMfXr8=;
        b=b5iXNY8kXINGHzrdlXg6yaRWfxpdfswVpkvYl33ue7106XwWvDXjKJxMjOAtVi8OQe
         TxWPg0pUThigna+UDFLyDemriwn+mwf7HhrvxsmiOBbh3Hz7MDYwjN8fhcOnQhWBJoBk
         S0s/RXMtffM8u5amD/EXWQKHTAOZwePQiJPRxqqBgZ3+qv5QMQ/Z2bwIUNPiHowIrEjt
         EwfI8MkA/xMcgFlYdpFH/2HHzrY50XJdHfgE/mk4UoI/1dWG+ZrMg1XrajgKu9xNNhEt
         ZPDVI6GqBc9RzUEbPiNZKbO2SFOymCC4gJimE5JOfre5JXBFcRS01smZJLVrDphudbIX
         wagw==
X-Forwarded-Encrypted: i=2; AJvYcCVXkvU9d6gi3/HgW+ktLNleWVYTkGeBW5z9kSPSNBoQSQsk1XW9eTJcLxlh8hgQf3415UCYnA==@lfdr.de
X-Gm-Message-State: AOJu0YwQnG1bhbxPVFxNJAHnV3JWpK3O8gj3ZVxMzazM157dwSXiYRQ7
	ZwCscqd9QiH1aA2H503Fyrn23yw4LtOsO1j6Ylt+qW0+C6SqBW5+8uIf
X-Google-Smtp-Source: AGHT+IGd9YfCCkuYj50wCV1pHiZAJ8pbsIUDLc6kzINjFSs56gzg/FFwS0eCazLueVEEjhBpG7V7oQ==
X-Received: by 2002:a2e:a54f:0:b0:37a:4bab:ca09 with SMTP id 38308e7fff4ca-381215671camr9011091fa.6.1766159191916;
        Fri, 19 Dec 2025 07:46:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWY9/t5rceeEo+NWuUDKc7lUoJh97Lx3ZQTYSsXue93Jmw=="
Received: by 2002:a2e:90d3:0:b0:37a:7d5e:db6e with SMTP id 38308e7fff4ca-37fcf057229ls10006121fa.2.-pod-prod-05-eu;
 Fri, 19 Dec 2025 07:46:29 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCU6QdBzb7QOCHRfRYuE3paqSknBZOzAmgOayMetbAmo6aeIOrTc3q7OuxC52hJnEBO3U61MyCJOE0A=@googlegroups.com
X-Received: by 2002:a05:6512:39d2:b0:597:d64d:1d02 with SMTP id 2adb3069b0e04-59a17d5a50bmr1374864e87.43.1766159189129;
        Fri, 19 Dec 2025 07:46:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159189; cv=none;
        d=google.com; s=arc-20240605;
        b=C4AXW37ANEv4x7l4+a1ZRGesHoU1fNi9LXB13/RT2yYTM8+1Yr+ISbs8OjCSv6EKV2
         3ZPbnmZDKg4vkWw7I8dke50sebn4kEyx/8fLlUnf5q7TNt899PH2B2hQu2A9m1L/A0ps
         CljK6ghLThHzpUSCKk48JB5SKP0l93cOKG4IBstnkw6R/tLEtukpC5Qs4E3xNZ+yvMIP
         1qzi5E4TDaFdRszGRRX6sh1m4Hd8w+toJlXsVCldiSBsyjRxZKFqR8TJrW+rjo4Jpv3I
         VFW6u31M+qW6N3ARXv5UMTLImhJpCVBqqBJuy6nMtrJCfTwjf47/ovMcQ5UCnYQKpjTF
         ZAaQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=JNejWFdtMyTjodgPbCP3MYwy/kg9I0zeQniFTuJdWnY=;
        fh=8cEtw3+c9Hvquwj9OJoBkm3rnR+YWkh+Q5ddyeShrzE=;
        b=URLvz2PzJbDszX9oA72DUa0QvDgUgXw7XcbN4GW6Glp1YaEoW+SuSJlAvUY3QU5l9p
         0FcY2sHKqDS8ip3kEelLv9IuXZuBtTEVx0z2SkGk27kcG291syGK7mCTA3mg7IOw0MQU
         Awox2vE3Xg/sJvrJqd60gAxIQ9hDfORH7+yCoBi/bzmsV71pHRb3NVbiHTPkBsKXlzt5
         xgpkFYrTLhLjJ05ItnNoWXSNullyVKum03Q4QGXGUtlK4kIWKzQDTrix/Eo7WDhEo4p2
         +NCAcPl7YNBTadNJboDMZxh8fKSDv8uqCFH3/wqGsuvGI/6mEimZxVbZBYpRxI8oQiAu
         s+7Q==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=BLOC63QA;
       spf=pass (google.com: domain of 3vhnfaqukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3VHNFaQUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-59a1860d04bsi83400e87.4.2025.12.19.07.46.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:29 -0800 (PST)
Received-SPF: pass (google.com: domain of 3vhnfaqukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477b8a667bcso23230855e9.2
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:29 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWx8O33/l1QvOIYL+v3cPmb3zRXLunwBevl5VyfG/9WKS/9m7e1b7edOMkl5/m51ltcQVQIthdrmSk=@googlegroups.com
X-Received: from wmbdr22.prod.google.com ([2002:a05:600c:6096:b0:477:7949:c534])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:820d:b0:479:3a87:208f
 with SMTP id 5b1f17b1804b1-47d195aa085mr30273655e9.36.1766159188650; Fri, 19
 Dec 2025 07:46:28 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:05 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-17-elver@google.com>
Subject: [PATCH v5 16/36] kref: Add context-analysis annotations
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
To: elver@google.com, Peter Zijlstra <peterz@infradead.org>, 
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>, 
	Christoph Hellwig <hch@lst.de>, Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Frederic Weisbecker <frederic@kernel.org>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Herbert Xu <herbert@gondor.apana.org.au>, Ian Rogers <irogers@google.com>, 
	Jann Horn <jannh@google.com>, Joel Fernandes <joelagnelf@nvidia.com>, 
	Johannes Berg <johannes.berg@intel.com>, Jonathan Corbet <corbet@lwn.net>, 
	Josh Triplett <josh@joshtriplett.org>, Justin Stitt <justinstitt@google.com>, 
	Kees Cook <kees@kernel.org>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Lukas Bulwahn <lukas.bulwahn@gmail.com>, Mark Rutland <mark.rutland@arm.com>, 
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>, Miguel Ojeda <ojeda@kernel.org>, 
	Nathan Chancellor <nathan@kernel.org>, Neeraj Upadhyay <neeraj.upadhyay@kernel.org>, 
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>, Steven Rostedt <rostedt@goodmis.org>, 
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=BLOC63QA;       spf=pass
 (google.com: domain of 3vhnfaqukcaefmwfshpphmf.dpnlbtbo-efwhpphmfhspvqt.dpn@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3VHNFaQUKCaEFMWFSHPPHMF.DPNLBTBO-EFWHPPHMFHSPVQT.DPN@flex--elver.bounces.google.com;
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
index 88e82ab1367c..9bc6abe57572 100644
--- a/include/linux/kref.h
+++ b/include/linux/kref.h
@@ -81,6 +81,7 @@ static inline int kref_put(struct kref *kref, void (*release)(struct kref *kref)
 static inline int kref_put_mutex(struct kref *kref,
 				 void (*release)(struct kref *kref),
 				 struct mutex *mutex)
+	__cond_acquires(true, mutex)
 {
 	if (refcount_dec_and_mutex_lock(&kref->refcount, mutex)) {
 		release(kref);
@@ -102,6 +103,7 @@ static inline int kref_put_mutex(struct kref *kref,
 static inline int kref_put_lock(struct kref *kref,
 				void (*release)(struct kref *kref),
 				spinlock_t *lock)
+	__cond_acquires(true, lock)
 {
 	if (refcount_dec_and_lock(&kref->refcount, lock)) {
 		release(kref);
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-17-elver%40google.com.
