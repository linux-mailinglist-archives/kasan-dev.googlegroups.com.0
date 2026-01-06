Return-Path: <kasan-dev+bncBCAP7WGUVIKBBDUZ6TFAMGQEM66GYNY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yx1-xb13b.google.com (mail-yx1-xb13b.google.com [IPv6:2607:f8b0:4864:20::b13b])
	by mail.lfdr.de (Postfix) with ESMTPS id 36DB6CF8792
	for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 14:22:24 +0100 (CET)
Received: by mail-yx1-xb13b.google.com with SMTP id 956f58d0204a3-6455532d07bsf1229153d50.3
        for <lists+kasan-dev@lfdr.de>; Tue, 06 Jan 2026 05:22:24 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1767705743; cv=pass;
        d=google.com; s=arc-20240605;
        b=i84x2S0w0xA/fjXNCGlpFAqUqoo5ZSvvKu+tm0dF/ieDatnOi+4Oz9BVz7KmYQzrXK
         q/XInseuOv3tZac0AukY6hIjG3iQ0PzUNoNHRc70/12yhQ9+7o7X+lGJplwOS493AX8S
         +x4X/gGPls+InzDhbSeE0DilO88xnKTX44r+8vH1L1EfMF9kF6WaMisaWy7YraxJiZXB
         qQqoe6n8/ZHN2ZKcqbiPYeTTaUvSvZ55/uG1OkT0ZEXQs58bh7JRHG2xqcL2RUI0A6HO
         dd7uH8y46x+fwf5fjkh7viStDfIje11nZOi4c78AG/0395gfGW8BvV4idNKzl6EKJ2qf
         //Jg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id
         :sender:dkim-signature;
        bh=WqoEruSQIxt1FImNGwML12cqoXEHLJw0Jx9/NmwDsPo=;
        fh=9zKLWVb0aTqI0g6WZJfiMfSInaDJTomwkt8UTlssxw4=;
        b=HPfUupPGZmiZXmHwtFYhfig2shM0oKMV6wxkxppVI1TfFmwdYpZc7QchP+/YZ8TeDs
         UfKyedBJHL/obbjz3qNCMDe/69ptTOYbzzD0dx713hsdrH+aMqs1d/oCTMu4GRYdNC9q
         ZPi57dDVDLG8wmcyq4s+pZeglJfU1i/1lFZMdoYF0yAzH2Huw6u7hEp9Fz6qT60T1pmy
         kUZKNHI/tsfJ31z9ZrkPm35gc7r+sZoU4rOPJdMyWtgcgsJdjjqX2iC7udNPSiUiPxnh
         GO4XNYv/2UE+HSVBkSukjDKZOq38su1gxHZnlKl7SZxeZTWoC2YMwVxAoz8aV40mbwyk
         gVZA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1767705743; x=1768310543; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:from:content-language:references:cc
         :to:subject:user-agent:mime-version:date:message-id:sender:from:to
         :cc:subject:date:message-id:reply-to;
        bh=WqoEruSQIxt1FImNGwML12cqoXEHLJw0Jx9/NmwDsPo=;
        b=OXpAjUEsAbVQk8XL7xky/1BTpK+NSFpIIGvnCeZa1D0ME3b4yNBWIhQ8WStC8Tbtf1
         17hSrgnacdyTsdwc6+tu961cYqT5uwPOtDO3fNJoer0d5Fy+fVvoJBfwxHGAuQ/OI475
         D1pm+zC3XEXh1ksMMFMnw6Gsxuzgg7G4z7IpPi6GQbw7W9gPCyP3zKwdo3YrSZ21M5Hw
         /trEW0kuGavAtfF83EJxd9GL7LIykgfy+1bMx7Ox2jMhuWfXoNWY+6+/1tZW6LkXVLUJ
         zwFo3wcV2LLZoSmSyeDBi3PrHJRwt690peE0TmjFVFlEwjwGfHvheiY/vdCGowl6C+2f
         8cuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1767705743; x=1768310543;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :from:content-language:references:cc:to:subject:user-agent
         :mime-version:date:message-id:x-beenthere:x-gm-message-state:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=WqoEruSQIxt1FImNGwML12cqoXEHLJw0Jx9/NmwDsPo=;
        b=qAAhBspoc5Ke6Pjue1AU0rkPJ0aqx5R31ffladhqzbxM72uoKdMbzwcNPPrO7VWyv4
         TGAx0IG0Ob3f86bZsn11+40KENjFJNT/ZJ8X0O/WqgLKk2YCDnXRFo2COq7EkYBYB0a5
         KivWrk0/6PpK/uD7niSoAQgDwCbgW6x0QZfaicm/AWzCjioobiwMKDAzM5dE2qI+ar+d
         7+PY+T48RTTwV/JnZrtTU7xtxNEIgX6UilR7b4aEGawf15SjgjIJOeTb+q3/iBDWTLq8
         Zu7ZTSTg1Gp+vpxbQbQ9FgOejAsNecjxldYKahMB2HWxHeyLCg4Ob0q7X8iqI6qXDASx
         nhSA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCV5ys7mIGrLscBStON4jYTIqj+uyd9gPONllhsIRohtzZnYCo33uAFqkKsQwSfXFFpn3H9NGw==@lfdr.de
X-Gm-Message-State: AOJu0YzNVHb1ISGquGyrv1g21WyJEeH9Qhv9fGajgNGqaGqpEwtz8eeb
	ktoM/mn6kuwC7toz5wGsYmgAb2Elr//8VsLNMyjf9e7EmcS+qHu5mEiL
X-Google-Smtp-Source: AGHT+IHwmmUOIcgBJSxdzZG/mW9FvMh2+HIxfZI8+MYuYCYKi7npW+GHK9Qusto86JG/PhB2q/eGPQ==
X-Received: by 2002:a53:e229:0:b0:645:591a:cb6a with SMTP id 956f58d0204a3-6470c90f634mr1537154d50.70.1767705742655;
        Tue, 06 Jan 2026 05:22:22 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AWVwgWZLobgbQhmmA3FJCYnW0jRT8u7VcnsGN6Vs31YTzBrHyg=="
Received: by 2002:a53:ef85:0:b0:644:730d:6219 with SMTP id 956f58d0204a3-6470bd2608els790714d50.1.-pod-prod-05-us;
 Tue, 06 Jan 2026 05:22:20 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCUjUB0jeNYj5GIyXRYC7IHXsUr3Lg4vKbX0aZjpbmuFDNXYqvOwVEqNH5xTgcejH70V4i9ka0mDWSs=@googlegroups.com
X-Received: by 2002:a53:cd8a:0:b0:644:4a95:c15 with SMTP id 956f58d0204a3-6470c931a52mr1521666d50.80.1767705740745;
        Tue, 06 Jan 2026 05:22:20 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1767705740; cv=none;
        d=google.com; s=arc-20240605;
        b=RHwNxt5JAEb0pGxAWW6ZAcDE7I6e9lTpdPV9DWzGC3VVOQU5U1RuRmIuVClwUtlVL/
         sLdTu0pcaFNtjp0fEZ4fMmm5q7BFVXWZOw7+uuSerbVem2onaAHTUFlkApWVvqGYvVE1
         0mSvSlx9LXRp9hk5vWG2eeO4Z3ZHu7IoW5+jYdQjv1j1hPTZB+sDL6WhgU2tbZfDuhMP
         xJDtFpSVWr/TiLIt9AI06JohH4T5VNk7QqMN/CcmBiiKWunkvUBd87YRPJHa2WF/l8j8
         BQW6tU2dWMg0R1ANIT53nkMLarrxzkOcPggLTcs2Q2QqHolTYsAzr8lZ+W2ex5E31Mzh
         kgGQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:in-reply-to:from:content-language
         :references:cc:to:subject:user-agent:mime-version:date:message-id;
        bh=j0/XcQ4MyKbdRtIFVSuEfvR9IygVIY0KqI25WDHpKpc=;
        fh=XBlIYqEp49yMK9A1EeafmmEzjuqDsnHWr92RHtg5tbU=;
        b=OoUX70n2okDNvEnYX5B512MXW0nYSLDxr2oMRYnYjlAloKH3YbmbEf7fvQ04jjaZWv
         HxSZyq4rdo8bGSr7VX2TIRCcNqsAjVhadxuCbnPTlZwEe+f9mWDHIxO6OFISZYXOzG3W
         G37epVLodFj0b8C9c4ZWtBl569XejU3iHQgJv0Buh07uhKTen+cUTXKUREyyoo4rFFlL
         ffFPlNhHtbKicb/RgrC915GTKgzdIk9Z7qWYjM9Vth+0gmhbZQjvn4eelMvo0ysPu94B
         HntMpulfsQPPKtGvckXOrQrA9qCJK46IN+y7JGzVJfRS8QWB8ZM/CxNo19SfqX5AmsvJ
         Ghqg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
Received: from www262.sakura.ne.jp (www262.sakura.ne.jp. [202.181.97.72])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-6470dfde82fsi93174d50.0.2026.01.06.05.22.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 06 Jan 2026 05:22:20 -0800 (PST)
Received-SPF: pass (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates 202.181.97.72 as permitted sender) client-ip=202.181.97.72;
Received: from www262.sakura.ne.jp (localhost [127.0.0.1])
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTP id 606DLekF006168;
	Tue, 6 Jan 2026 22:21:40 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Received: from [192.168.1.10] (M106072142033.v4.enabler.ne.jp [106.72.142.33])
	(authenticated bits=0)
	by www262.sakura.ne.jp (8.15.2/8.15.2) with ESMTPSA id 606DLdft006165
	(version=TLSv1.2 cipher=AES256-GCM-SHA384 bits=256 verify=NO);
	Tue, 6 Jan 2026 22:21:39 +0900 (JST)
	(envelope-from penguin-kernel@I-love.SAKURA.ne.jp)
Message-ID: <993d381a-c24e-41d2-a0be-c1b0b5d8cbe9@I-love.SAKURA.ne.jp>
Date: Tue, 6 Jan 2026 22:21:38 +0900
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: [PATCH v5 06/36] cleanup: Basic compatibility with context
 analysis
To: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
        Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
        Will Deacon <will@kernel.org>
Cc: "David S. Miller" <davem@davemloft.net>,
        Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
        Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>,
        Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>,
        Bart Van Assche <bvanassche@acm.org>, Christoph Hellwig <hch@lst.de>,
        Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>,
        Frederic Weisbecker <frederic@kernel.org>,
        Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
        Herbert Xu <herbert@gondor.apana.org.au>,
        Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
        Joel Fernandes <joelagnelf@nvidia.com>,
        Johannes Berg <johannes.berg@intel.com>,
        Jonathan Corbet <corbet@lwn.net>,
        Josh Triplett <josh@joshtriplett.org>,
        Justin Stitt
 <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
        Kentaro Takeda <takedakn@nttdata.co.jp>,
        Lukas Bulwahn <lukas.bulwahn@gmail.com>,
        Mark Rutland
 <mark.rutland@arm.com>,
        Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
        Miguel Ojeda <ojeda@kernel.org>, Nathan Chancellor <nathan@kernel.org>,
        Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
        Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
        Steven Rostedt <rostedt@goodmis.org>,
        Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
        Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>,
        kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org,
        linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org,
        linux-kernel@vger.kernel.org, linux-mm@kvack.org,
        linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org,
        linux-wireless@vger.kernel.org, llvm@lists.linux.dev,
        rcu@vger.kernel.org
References: <20251219154418.3592607-1-elver@google.com>
 <20251219154418.3592607-7-elver@google.com>
Content-Language: en-US
From: Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
In-Reply-To: <20251219154418.3592607-7-elver@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Anti-Virus-Server: fsav101.rs.sakura.ne.jp
X-Virus-Status: clean
X-Original-Sender: penguin-kernel@i-love.sakura.ne.jp
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of penguin-kernel@i-love.sakura.ne.jp designates
 202.181.97.72 as permitted sender) smtp.mailfrom=penguin-kernel@i-love.sakura.ne.jp
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

On 2025/12/20 0:39, Marco Elver wrote:
> Introduce basic compatibility with cleanup.h infrastructure.

Can Compiler-Based Context- and Locking-Analysis work with conditional guards
(unlock only if lock succeeded) ?

I consider that replacing mutex_lock() with mutex_lock_killable() helps reducing
frequency of hung tasks under heavy load where many processes are preempted waiting
for the same mutex to become available (e.g.
https://syzkaller.appspot.com/bug?extid=8f41dccfb6c03cc36fd6 ).

But e.g. commit f49573f2f53e ("tty: use lock guard()s in tty_io") already replaced
plain mutex_lock()/mutex_unlock() with plain guard(mutex). If I propose a patch for
replacing mutex_lock() with mutex_lock_killable(), can I use conditional guards?
(Would be yes if Compiler-Based Context- and Locking-Analysis can work, would be no
 if Compiler-Based Context- and Locking-Analysis cannot work) ?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/993d381a-c24e-41d2-a0be-c1b0b5d8cbe9%40I-love.SAKURA.ne.jp.
