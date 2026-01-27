Return-Path: <kasan-dev+bncBC7OBJGL2MHBBXFB4LFQMGQEGDV62AY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mPCIB9+QeGmirAEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBXFB4LFQMGQEGDV62AY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 11:18:07 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103e.google.com (mail-pj1-x103e.google.com [IPv6:2607:f8b0:4864:20::103e])
	by mail.lfdr.de (Postfix) with ESMTPS id AF5CA929DF
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 11:18:06 +0100 (CET)
Received: by mail-pj1-x103e.google.com with SMTP id 98e67ed59e1d1-34e70e2e363sf4924534a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 02:18:06 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769509084; cv=pass;
        d=google.com; s=arc-20240605;
        b=PaaDWJeQjO00a7/9bax5Y/cg8OLD/ykTd0Aoi1a7L3G6PGhcbA+9FlU8WkGYhoac2h
         hxelqMQAWGKvhOrhbcr4fY6l4bSfhPGcexilP7Nf3jOAuPBO+fKB9PZmWVToPl0DE/MT
         j+65WOEEYiuuntZ3vE5FtAQxasulDMVkNFaxA7fySYy0RgAjok4875BvyqWapxWs6VA9
         nkbeChM3sTA1nh/fMLY1m9A0Q5LpV269aiTA/ZyIvXxv8JNZ31sm/sSH2b8lR+dtIBqq
         v4TQpG2sn0KVRI0V83BfJmkRLWzx6LfxiMnt5AXtq6hExTYF6Z7NK9VUrM20ZA+zQGur
         p82w==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ifqV9pXbvl83i4xDXZ9TZsefvxGsmO21VHMqLoqkQno=;
        fh=2tQc+iShVe1ssEWltEWhfPWoUiDHP9IKs8PwmKD17yI=;
        b=APHAqMDYQmxGam124mxSCCzeOKdTUqZ4EVa4Bed/Dljmq3lyeE0Wbai223OXlG0Apa
         31LUexiGYSLDRzVxQrEEtvJDeMQI+VFhD8ci+ihQ9FpfKKNHK6dm++KVTKFO4xGnNohm
         oSgCxVPjjdjlN0XKGZTLkNhLIrODFYP5lEzaKwQ/aM4vzSqtyhS2mQtOafPD1M8QT7x9
         5POD1MZE/9a8KgqB+oN+gr0yXd5jRhM+LS/+Vb10fJkGBvf4qO/8ZoD5FygogykZoPEy
         rKnz4DLGMFTgH3Ui3SjUqekZXGxN1I3aUNrzhHIEAgnQKodJH19qY1ooBM6VOnKwuzko
         Xtjw==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=at1t4CpO;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769509084; x=1770113884; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ifqV9pXbvl83i4xDXZ9TZsefvxGsmO21VHMqLoqkQno=;
        b=lChv0LUJ5v2Gafkw7GGnt9mRQcE659hqh0d99dOGBIjqKmk96WpvrByExd+42XSlAN
         PdwSGc3GQAGLb7bm4jTFlrAGutzwU/HP/sDHrLkTbcgbjh7nukxlqbqD4qb9Fgi8QyMl
         XwQ+AmNNlrjPOtnwbUQQ9UAq8h99UxrgRrKqPjh7R8JNlU2z6i2RaG7mxXL9O7SVj6vi
         /K9he7B/an/7xmovcyG4FejcNif1M317CuGS6sVvbeOKSMSeyzT8FMVeMbQTmjDYow9h
         2gTVLsnXKZq0IMi7sHmJXwk1uyce7oXip97YOBI7WO+OfnbcPvIUFvQ5GOpeUCndednR
         vkyA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769509084; x=1770113884;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ifqV9pXbvl83i4xDXZ9TZsefvxGsmO21VHMqLoqkQno=;
        b=auNmVA4baZDR9HifH3LJhjjoP3+XBxJ3BKf7K8XtPsymlwmNnSr6oRpyY7EGRoRNSW
         L9P/77FW16SPG8fMk5aH5DUwwG4HPV0pN6ubeOFaUhWWqTAv41kbRxwJc4W6AYuWjEAq
         RREDi/bIVReEt5+6hOhwEFZpUgZ07DGEwdpkkMzQK0D9uvb81RoOBj5DVNRCJ0SLCOK5
         k9lR6Z6z9nX0uk/HBKuuNnKTbH5kwnQjVUSEAIvsxqyOFBnbeowv+7uamJ4RTkDN7xtQ
         YosXRfsPLDrTgLRXd5thYZtbX90P6di+jQ26tRZPVqo3MuPxb4JcGOFx7xtXI8Iu/cCh
         MNuQ==
X-Forwarded-Encrypted: i=3; AJvYcCUxT1BFhziiik0/Z1+yk5Sc+yKRHNRalzZjFS4jFr/oiBiolRa9wSVv4W3lkqbL6agUU16MXQ==@lfdr.de
X-Gm-Message-State: AOJu0YwYM7rVzOrpqAUlGP4kFAUnIDXqTKO+nf41AzkhQlUHFsXR79o1
	ittgD/FxPbdgGy86ISX0nZrA18MNV+rQCEvk70y0rjSs0RnEYzqgiiwk
X-Received: by 2002:a17:90b:58ce:b0:34c:6d33:7d34 with SMTP id 98e67ed59e1d1-353fecf6accmr1329832a91.16.1769509084593;
        Tue, 27 Jan 2026 02:18:04 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+Gshcg0DHuoYzpQ0whaZIDWB4KYrdAGH8UlIZ2wU9msgw=="
Received: by 2002:a17:90a:710c:b0:34a:4cd5:6c28 with SMTP id
 98e67ed59e1d1-35335a69057ls4044350a91.1.-pod-prod-01-us; Tue, 27 Jan 2026
 02:18:02 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCX/lzq5ltL/AshUm2RaSbyFZ8ELKEniS5wzxWWopW5fh6aEwXtYKvpuPYzmvNkYXDR14j7v9yF5J/I=@googlegroups.com
X-Received: by 2002:a17:90b:1dc4:b0:352:d1a4:19cb with SMTP id 98e67ed59e1d1-353fece529fmr1342178a91.11.1769509082606;
        Tue, 27 Jan 2026 02:18:02 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769509082; cv=pass;
        d=google.com; s=arc-20240605;
        b=TE7Cv3uEuAhTfUCcHiYaXIZHBjsEd+5Gdi5yqjTdmC2F+cl9YMcSnFL7yTR9mQmPOp
         fyvdPC4mHdl0uH18Cn/eMLn7qR79ByJW97+tiFwM0Bu+SFOQFiM+ED50DIj1jFDJCZ59
         9gJAlflPvvzTOZWpOpa/9Z/4FtqjXscYiKoPVF2CvktV6tXqCU8m31QzvfxeLffMOsld
         GkkeH1cuLzUP6YOZbt7iSNREhRqcIzTyzW9gbLQhjTqa2ALNoZ9wMh7Lrnqi94g/RxDS
         LyO2DM7xbLxmvrDf3vt0epit/+DlXmprHDUvTUIlUFksF7heUexIoU+E9J43dmXnHtln
         NLEg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9eWZA1QTRdZDTddGYL8SlE552QBQW/sLGGoi37wJCfo=;
        fh=8QhZaRlbhuzspIgnSEjV8b0QwMEEbATx//U7/C47VhM=;
        b=SgKsMv2Q5yWlLBQqxEp3eT5OgZJevNIDWq4UDRjp/0TuK1ZMVLXgjG5E+AYpp8vzy6
         9vwu4dJg4Covi8BD2uVSXm7ygGTtq0RAW0+ySeSbnD2NtiMqfwWUxx0aXQpKeVoxxV10
         Otx1cOJJakmj+n6TdC1z7jJ7iQNwgDaGFo2W1wfk3Dm20Vwi9fHFDnnWg1A21PGkWbjC
         lUQM0VvXnpXzvpzD0ThpC+TDW+/z7t0OWkwEHBQXB94GzwTQaLjTPrbKWXiuDdjPNmNd
         oDfZ2ik04JXu22OVkPgk9mfb7iXthWpW7hjoImc9EKv4FbtqOFpSgFsPN9LYkalY74cE
         OG6A==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=at1t4CpO;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1233.google.com (mail-dl1-x1233.google.com. [2607:f8b0:4864:20::1233])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-8231872d897si415429b3a.6.2026.01.27.02.18.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 27 Jan 2026 02:18:02 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) client-ip=2607:f8b0:4864:20::1233;
Received: by mail-dl1-x1233.google.com with SMTP id a92af1059eb24-12332910300so2129441c88.0
        for <kasan-dev@googlegroups.com>; Tue, 27 Jan 2026 02:18:02 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769509082; cv=none;
        d=google.com; s=arc-20240605;
        b=C+KUoPeOXNaZMbq0dO4x2utf+0pnLqOjYUwf713UB4aDwLkGaeTRZ6DB+6mYi3BMLZ
         8KA7aL9HYPlniPS7ZB9j0FUcE/irEOcFrINPj9DG6OO91VYQSy9AmJvLnZAtaGNWqJ40
         oTgEVieda9rPqUIWhv7IkT7wrYlciAJm2spkAdsyysmxIIRDPsnmYeYnTt1MAAfblNU7
         ZZSHABNH5V4a/1c5BR8uC5Sc5nQ6yCFTA1+JVrcdD1AYGdXTIb0h5sirwZptRJBMYCED
         JHOooqySl+dy4gYyrkq6/GY+0t/k/P9sb0LecIFwGGMjhVCetaxT0qVdeJ6ulVl7Cmxw
         bCfw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=9eWZA1QTRdZDTddGYL8SlE552QBQW/sLGGoi37wJCfo=;
        fh=8QhZaRlbhuzspIgnSEjV8b0QwMEEbATx//U7/C47VhM=;
        b=a2quzPfzJYlKhNyMik16YGGa6Isvz19xR3QO6zT+q9kTEI0Tme1eL5UsgJn6FQnZom
         APKBljklM2cGzYYJxweCo4tYkhNZ8mmx1qqB56CFxhaLHvzNB+ylqmHptvyaWRPcyU4H
         HtpAmfnk1u4QCacdYDR46/Z9u5lU7mrpVJxO8J7m+VXJO43ykAnmcS7mlkVKin2kWhtq
         OB4zRAEHy5T2x95NVtP9D94qwdg/1x93tr3m3Xw4QF6pgl8t9qpNna3cjPT2ctbbXCAq
         WYv+jno+uVzI1OPwmOf8cDllW8FxvhqiueDjo746iY1SMpcbHxN5rQNZJFsnRIeFsb4M
         zopw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUqYHbSt2D2TIwpzeypF5oMsDvS5G0Jfysfgwb/z4jjC5JVLJbdrTcVX9Pfs2bjKZ6PkfNzvKBLSw4=@googlegroups.com
X-Gm-Gg: AZuq6aKdrQqwSTMYyWFr2UVyy3CEe8Dewp5Gnwxq5xyI1/eIM36PWbwVqe2wnztV7CB
	3e8s51seNEuljcwa3ASAGBBAgEz60kcZKxsqurY2v/4eg6JB0bvmWOREhpI6x7YQ1m+tB6ku/vZ
	pTizhXpBun4BCqRvMAzDhMqr2WB2YIuSkUyuWkC/lF4BZ9jWndUlx+ACL05K4xaLXrbcPpGT/GY
	HiSUieGdaZ91rf1lNoKw68ozkvYo38Z1NNnloZs9kB1h8gz+qDtJck62OxTG1VZ+vpbqwJUMNZX
	fjhPMfhMUfpeM1g6ghV8IU4zPw==
X-Received: by 2002:a05:7022:6985:b0:11e:f6ef:4988 with SMTP id
 a92af1059eb24-124a00cd55dmr806676c88.36.1769509081547; Tue, 27 Jan 2026
 02:18:01 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-7-elver@google.com>
 <0c2d9b69-c052-4075-8a4b-023d277b8509@lucifer.local>
In-Reply-To: <0c2d9b69-c052-4075-8a4b-023d277b8509@lucifer.local>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Jan 2026 11:17:24 +0100
X-Gm-Features: AZwV_Qj2UVNnjgQTvKRMxq0N2rMz8K4yMXQyPWTkZbJrWul7iRYbem2vd2u4cZs
Message-ID: <CANpmjNNHmOzaCSc9hQJNuzNVHXA=LRgXB4Q69FNk6wBuuJGdAg@mail.gmail.com>
Subject: Re: [PATCH v5 06/36] cleanup: Basic compatibility with context analysis
To: Lorenzo Stoakes <lorenzo.stoakes@oracle.com>
Cc: Peter Zijlstra <peterz@infradead.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
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
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Thomas Gleixner <tglx@linutronix.de>, 
	Thomas Graf <tgraf@suug.ch>, Uladzislau Rezki <urezki@gmail.com>, Waiman Long <longman@redhat.com>, 
	kasan-dev@googlegroups.com, linux-crypto@vger.kernel.org, 
	linux-doc@vger.kernel.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, 
	linux-security-module@vger.kernel.org, linux-sparse@vger.kernel.org, 
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org, 
	Sidhartha Kumar <sidhartha.kumar@oracle.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=at1t4CpO;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::1233 as permitted sender) smtp.mailfrom=elver@google.com;
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
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-0.71 / 15.00];
	SUSPICIOUS_RECIPS(1.50)[];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=3];
	DMARC_POLICY_ALLOW(-0.50)[googlegroups.com,none];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBXFB4LFQMGQEGDV62AY];
	RCVD_COUNT_THREE(0.00)[4];
	FREEMAIL_CC(0.00)[infradead.org,gmail.com,kernel.org,davemloft.net,chrisli.org,google.com,arndb.de,acm.org,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,i-love.sakura.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev,oracle.com];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	TO_DN_SOME(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	NEURAL_HAM(-0.00)[-1.000];
	RCPT_COUNT_GT_50(0.00)[52];
	FROM_EQ_ENVFROM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	MISSING_XM_UA(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[oracle.com:email,googlegroups.com:email,googlegroups.com:dkim,mail.gmail.com:mid]
X-Rspamd-Queue-Id: AF5CA929DF
X-Rspamd-Action: no action

On Tue, 27 Jan 2026 at 11:14, Lorenzo Stoakes
<lorenzo.stoakes@oracle.com> wrote:
>
> +cc Sid for awareness
>
> Hi,
>
> This patch breaks the radix tree and VMA userland tests. The next bots didn't
> catch it but it seems now they're building the userland VMA tests
> (e.g. https://lore.kernel.all/202601271308.b8d3fcb6-lkp@intel.com/) but maybe
> not caught up to the issue this one caused (fails build in tools/testing/vma and
> tools/testing/radix-tree).
>
> Anyway it's a really easy fix, just need to stub out __no_context_analysis in
> the tools/include copy of compiler_types.h, fix-patch provided below.
>
> To avoid bisection hazard it'd be nice if it could be folded into this series
> before this patch, but if we're too late in the cycle for that I can submit a
> fix separately.

Thanks, I saw. I have a more complete fix I'm about to send.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNNHmOzaCSc9hQJNuzNVHXA%3DLRgXB4Q69FNk6wBuuJGdAg%40mail.gmail.com.
