Return-Path: <kasan-dev+bncBC7OBJGL2MHBBWHGSXFAMGQEARETDIY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53b.google.com (mail-ed1-x53b.google.com [IPv6:2a00:1450:4864:20::53b])
	by mail.lfdr.de (Postfix) with ESMTPS id ECACFCD0974
	for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 16:46:34 +0100 (CET)
Received: by mail-ed1-x53b.google.com with SMTP id 4fb4d7f45d1cf-64b5d8c0c9csf2669368a12.0
        for <lists+kasan-dev@lfdr.de>; Fri, 19 Dec 2025 07:46:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1766159194; cv=pass;
        d=google.com; s=arc-20240605;
        b=QLA+Y1mleKPkQcgnQA05ME2rCO26ciURCkkecoR28u1EocwH489QfXKYWUL/a9Xjxv
         ep0z9hD9W2tTSwl+2gik8NFn2M8fD69lk1PnxiQRCafxkYCWeJCm9DlhV4ajKWUqF3Nc
         KtghyfmqCpWwHvGjDPl7A8AY2iffX4DguxZxsYejDjyrMAMpdWUTk0FO1CsNaoBNczb9
         B0TdNqYmikdMFkqAk9UCWejwm4jey+rk7OugNLwlQls/JVYvcL3i9UP63CvCq7Bp1cRL
         3EEArqyx3Pi7Ud+1qPDGgSm/Q7sgSw65zeiJnmsoUW1MKAjU5oHJ6HhATRH37z23x2zF
         iiIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:from:subject
         :message-id:references:mime-version:in-reply-to:date:dkim-signature;
        bh=VX6jLL7PauXQEkf7MPPXQULeP9e7g4kfaMabp1TaKpU=;
        fh=1kzQoqOZgGnG+h5qsLZ6mtlPTXxd0sbU9OkWZNILQmk=;
        b=We6yYyvFdyrg9skPqOqvlgPhnZ6DNMblOHwLfhp2Z2GQjDvkQSK9M3aErsnuJ4Akcn
         GA18a2cL4++gyQumceiUCL2iJUjaFsAzteb6wUyv4zuSQYj9d7X6o7I6Km8/v5kcAy2T
         1zReal0KUXI+/W5BccV4QbwNOWMNPrrfLdXfdXFsZHS9xtCAjfocaeHRHp4c1sAnmite
         pYOdTTYYQ80ZMe33gFW7R3oadskAjYlaBcmp7K3gpJp+0XjdVv9F5nCAA4fLzNxIqawI
         gHlIrwsQo5vN92dSa089wmNVY4gmNbXHg8xGp0crxXpQX5qHMVMINZndMXS3mTZ25dhg
         1gmQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XsqWunDA;
       spf=pass (google.com: domain of 3rxnfaqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RXNFaQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1766159194; x=1766763994; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date:from:to
         :cc:subject:date:message-id:reply-to;
        bh=VX6jLL7PauXQEkf7MPPXQULeP9e7g4kfaMabp1TaKpU=;
        b=hUksmHtWffvt4ZBjP+SOHPKWzID5oeXUqS1ojPb1tdzWjUYtRKGewdhBnUGxY9IlYr
         X6iHnkCgid5NvDxUhukNd4CyAIb2tqekmKn1w7U128LwTxN46AUe7YRyanPX3iIZ2ELI
         HS9nmjgCOqRV1EEt4BhNHhS2YU4yVJjKFpSZSyD09fxZ4DGenDRF8HQpYnwggaHiJWYW
         dxwPK8cA9Gl4VgaVu8TzmMKgZV9VTtR/S8hhx6nRGm1k+JBaWWamybbt17KukBggdrkD
         tPoxE764+9Bs3mRDxkGSyF6ZJZJZOjk6AhCAeQCYmkvX8L7Ro6kcokMNHthxkjnNiPlF
         dE1Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1766159194; x=1766763994;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:from
         :subject:message-id:references:mime-version:in-reply-to:date
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=VX6jLL7PauXQEkf7MPPXQULeP9e7g4kfaMabp1TaKpU=;
        b=rmIMzncybTIvio21+lHxQFh4e10s2e1fvwufT/ugId/PZfGiB0hUcv8SZsxq8MQHnG
         qXjnSbAGR4OT2n8pN79dDMl5Xk+C1y/CfalfdxdqdZSL+On4UbPZo+lhI805ZA/8uqUD
         1iKA5FxKZQ5XqZ7qiyGL9A+YKWlO25CkRwEyr3HfuJuooFbuzfOG3jFyYppdVcVZjitd
         9phN6dIkslSa5npSjdDqawFZ1DB7GTgqIaAjrBDEhZyilMD8RN01Dvtp1j+DHEKZJysJ
         XsNHksCDSwt5rqVqEYh7DxzXPdYkymN2UuvmE2SmFAbDafqoMdt8fPc7INQnbKvsAi9K
         RfvQ==
X-Forwarded-Encrypted: i=2; AJvYcCUMKgYRGMeNixW5hRivo3SD1HyTcM3AAfwoDkMplLUycu8qUR1OU8aD5FNNCXRnxNaVTSjCaA==@lfdr.de
X-Gm-Message-State: AOJu0YyhTwz0ulei/W6ubOABzIyIbZgzvrCvM4D4nt7rYUEAUEStrVKE
	kKq84s55FvuFkD3Ewm2l2DKZ+brc5uDQThjRytb4tTqUSuroaWlrPnCf
X-Google-Smtp-Source: AGHT+IE0uilBYe5/zgogtKTlJWpM6minbWLB6YzxAK30ln0/iwAdXGTn97dozsleA50LFeGxErqW4w==
X-Received: by 2002:a05:6402:146f:b0:64b:7ab2:9f83 with SMTP id 4fb4d7f45d1cf-64b8edb758emr3054267a12.31.1766159194242;
        Fri, 19 Dec 2025 07:46:34 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWYIdPjRZhDzN+uI8EiXJgZ+/RvtLkXiHjF9u0mNZvwT7A=="
Received: by 2002:a05:6402:5351:20b0:647:a4b1:7993 with SMTP id
 4fb4d7f45d1cf-6499a4150b3ls6770421a12.1.-pod-prod-03-eu; Fri, 19 Dec 2025
 07:46:14 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUHesW/aWtx6W8rvaur1nw55rtNhyGPlJd8X+p2bZR86W6d68COBNyG/Ff7v6ZTwRxyRhVLqvO8Ask=@googlegroups.com
X-Received: by 2002:a50:fb10:0:b0:64b:4333:1ece with SMTP id 4fb4d7f45d1cf-64b8edba915mr2519945a12.34.1766159174084;
        Fri, 19 Dec 2025 07:46:14 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1766159174; cv=none;
        d=google.com; s=arc-20240605;
        b=c311y3DbcL5+7E4XH3C+ije/H0PAtwrZey+tEi6cUsjujiDVuwn0tiE+zP3MaRhuG7
         tW05rJcPG6/f8rGOrArItXE20W0ppkP/Du+UCYZ4UqxCDA+RZec+9rmmJYwZP7rhpw67
         OAF01FC30q1UWGRZdvBMnjKYxs7fMtPQ/1rKLeSOrkusgP/ZqYasaeuHlCzpSqZc8GaW
         qpn5ZM2o5WYjbEHM72EWeV9EwawtNRNufqWp0st0XhPtiiC18T6U7iKh7sG6nwX8jWfc
         Q2kJG0jLGbVBZXRyQffVfojP0mveLfgzsUf32gopuL5pPgIUBFrzvVuCIaqzcmYMr7Tx
         cSeg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:from:subject:message-id:references:mime-version:in-reply-to
         :date:dkim-signature;
        bh=GzqxblqNylMZssrhkzyYMNb717UQfTl85zNKlM2THvo=;
        fh=kj4U9aHdq0frONzARVXQDOWQEvSFmn5MVRXtrNCQwP8=;
        b=hu3yHGaiWi9C2Z9xtBzOmup6zWX9oX6QBi8o/yHflvCgywMpEMHk5GuGfeEtCy20iJ
         4eqkde9LgWujdGqx5KoiOzd5mcj3IV8bmQu/UgTP9TGYstDLYn6wcjCEzcAaImwbhCD1
         jFsyz+Ox5Qk2jeTV725zQMNh+pT1VkH8M8aV9GRq9GvQdsm3LvJ6tUDbOFOTD5gmtlEp
         Xc5LsYTrUOd2riZp5efJDgDjW46SXJgadWU/J4P85PH0EqQh52H2Db43nh/1JvAZvTRQ
         ER6hZbxqenrsklhdxXlzZhhLDSBNtXPsJhuS1nRuFKtBrxf6uxL6C4pKuxGVvPG7RHbp
         gE7w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=XsqWunDA;
       spf=pass (google.com: domain of 3rxnfaqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RXNFaQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wm1-x349.google.com (mail-wm1-x349.google.com. [2a00:1450:4864:20::349])
        by gmr-mx.google.com with ESMTPS id 4fb4d7f45d1cf-64b913840e5si39730a12.5.2025.12.19.07.46.14
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 19 Dec 2025 07:46:14 -0800 (PST)
Received-SPF: pass (google.com: domain of 3rxnfaqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com designates 2a00:1450:4864:20::349 as permitted sender) client-ip=2a00:1450:4864:20::349;
Received: by mail-wm1-x349.google.com with SMTP id 5b1f17b1804b1-477bf8c1413so11133695e9.1
        for <kasan-dev@googlegroups.com>; Fri, 19 Dec 2025 07:46:14 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCWgO19grXDywZnWW6LiJnNyHYYyUI3A63KiZOlFtb8DQUSw5voX1kD0c32rtONpEqfIrWZXOj8xjU8=@googlegroups.com
X-Received: from wmqn17.prod.google.com ([2002:a05:600c:4f91:b0:47d:1d7a:6d40])
 (user=elver job=prod-delivery.src-stubby-dispatcher) by 2002:a05:600c:c494:b0:479:35e7:a0e3
 with SMTP id 5b1f17b1804b1-47d19582aacmr29774555e9.30.1766159173561; Fri, 19
 Dec 2025 07:46:13 -0800 (PST)
Date: Fri, 19 Dec 2025 16:40:01 +0100
In-Reply-To: <20251219154418.3592607-1-elver@google.com>
Mime-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com>
X-Mailer: git-send-email 2.52.0.322.g1dd061c0dc-goog
Message-ID: <20251219154418.3592607-13-elver@google.com>
Subject: [PATCH v5 12/36] bit_spinlock: Include missing <asm/processor.h>
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
 header.i=@google.com header.s=20230601 header.b=XsqWunDA;       spf=pass
 (google.com: domain of 3rxnfaqukczi07h0d2aa270.ya86wew9-z0h2aa2702dagbe.ya8@flex--elver.bounces.google.com
 designates 2a00:1450:4864:20::349 as permitted sender) smtp.mailfrom=3RXNFaQUKCZI07H0D2AA270.yA86wEw9-z0H2AA2702DAGBE.yA8@flex--elver.bounces.google.com;
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

Including <linux/bit_spinlock.h> into an empty TU will result in the
compiler complaining:

./include/linux/bit_spinlock.h:34:4: error: call to undeclared function 'cpu_relax'; <...>
   34 |                         cpu_relax();
      |                         ^
1 error generated.

Include <asm/processor.h> to allow including bit_spinlock.h where
<asm/processor.h> is not otherwise included.

Signed-off-by: Marco Elver <elver@google.com>
---
 include/linux/bit_spinlock.h | 2 ++
 1 file changed, 2 insertions(+)

diff --git a/include/linux/bit_spinlock.h b/include/linux/bit_spinlock.h
index c0989b5b0407..59e345f74b0e 100644
--- a/include/linux/bit_spinlock.h
+++ b/include/linux/bit_spinlock.h
@@ -7,6 +7,8 @@
 #include <linux/atomic.h>
 #include <linux/bug.h>
 
+#include <asm/processor.h>  /* for cpu_relax() */
+
 /*
  *  bit-based spin_lock()
  *
-- 
2.52.0.322.g1dd061c0dc-goog

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20251219154418.3592607-13-elver%40google.com.
