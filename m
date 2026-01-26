Return-Path: <kasan-dev+bncBC7OBJGL2MHBBD7237FQMGQEDNOSDUY@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id MFqJHhL9d2kvnAEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBD7237FQMGQEDNOSDUY@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 00:47:30 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43c.google.com (mail-pf1-x43c.google.com [IPv6:2607:f8b0:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id 9BC568E4CE
	for <lists+kasan-dev@lfdr.de>; Tue, 27 Jan 2026 00:47:29 +0100 (CET)
Received: by mail-pf1-x43c.google.com with SMTP id d2e1a72fcca58-8232a900306sf703352b3a.1
        for <lists+kasan-dev@lfdr.de>; Mon, 26 Jan 2026 15:47:29 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1769471248; cv=pass;
        d=google.com; s=arc-20240605;
        b=BQn8B3X2J4vVYuSo/ZL0m+oMnsvMAm7syyud2QwISt8pVYnQBoCTOcT8XW85ZRuKTP
         4NaepCMO8VHPwhvwPNW8pH1P+Sa75p5p2f0IGVs6r66DyFmfY7Nu31gvFJLXr0xtTHgq
         d9cBj9RpyiRrtk1NjIFjPBXgAuqlu33JFeA/XgEbINWL40x+l5XwaU/1MrBh5NLb4sJf
         +qdqwpgQu009/FuSJBCASQcXEc7GWvcuK5Eqfu20M8mYUS8W+yqAHAzA61F9CTaVVCoM
         ws+kmaMLz2EqUU8+oO6A1939e44+C1Wtp2Gjwid1MP/Mhhj2pN70x+vdUZzIQpMJb2qY
         urKQ==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=HS6pEd95i2Fgiq+pvkzHAqjOmB1pLg7saBwR9nKSXMs=;
        fh=4A5sqYOpm8/KlJhyMxeSZ2ZZGtOQyRUY19YoCR/Kgzg=;
        b=ZpoCQeVZX1JNLaIsZ5cXytSPswG4YS64IveTOX28/5LXkyfLE1ArFtbuSd3SErc/aU
         S2eYvwIXkjgipXtaQVbzk82YcpmbMLl1hCzrYsRV9roJZ9A3JtHuu0VMmfZYA2SMZ6fJ
         bSkytetE3I52zRqD/HgsswwxZ2gjLB7mYyILyDHT4hObzgJTxHTwM5+EQidCaybdQPmz
         x0MU29bHwd/xMPCScn9gJ3q8wEjQ+FWvj51gOFttzxkQ7wlCk4ra9BW/QFGAkwCD8vH0
         QjeG1dxOX8lLmIN7S5MW8wfR1UyHOK+fDiwpEhabpPyzvk1cFP4H1XvAckAOAKWE+LhH
         H2gA==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=STAMU9kw;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1769471248; x=1770076048; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=HS6pEd95i2Fgiq+pvkzHAqjOmB1pLg7saBwR9nKSXMs=;
        b=xCRuZPuOqd+dFIpmVRwFAeuFjDayBnW5pwrD4gH9dxgYHiPUH0+4xody1C+Me1lePZ
         k3bWN4h2EL4g/9Ajh3BOHFFxrKsOm+tn3xiQIvZ+ha6mc40rYjJbDbZqiSSDMEp43s/H
         yAPZBZC/tcY3tb38HvOWkWHIMvS0ls/SYYoTay6gVW7uZo2VR+CPYAIgpy4jmEX3+jXN
         G0me+D+UTZrwKfb90dItnxRaziX0qLHL3JFUboCxG4Jrrg53tKuEF2/0P3QBiJs+X4D6
         hlWPDX7FgHdNXbW6MP9LQHbjukXm8y6arWd85Pm1zLSGkPeZb7NvsqHQorKwR6CYXqq8
         lDtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1769471248; x=1770076048;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=HS6pEd95i2Fgiq+pvkzHAqjOmB1pLg7saBwR9nKSXMs=;
        b=q5g7HOjCiiYBNEF7SYBCUYrIgwzdfSuQX5c97/VuSTZMy4ebvIq8PEtD97mqu+QAh6
         +UvyHeyowtr3U8G5oHNb4uf4adIXMLymZt2H06Iu4tRm7ZDmJAv6mK7/eAo4KUMhthgV
         jI9HOKiN+MxH9BRn9yJkDAbl6FELfAEdo5Qzf/o6r3NY7TDbtDFoHfYj7TN13eZ4VdmP
         QJ9nDy6fRMKvFf9+sSmQstUyoaQXnl22XQN3OG98/9yfcDWbPCeeBGabOHdzfILqzA1o
         YcixetjDi0PDWg0hDLJ++Ap0wl8wbDwilYU+Lwzb3ixuK8j8EA55Vegyf5xwcniF4QZz
         YImw==
X-Forwarded-Encrypted: i=3; AJvYcCUE7Hd74Lj+UQpOfdUAAuE6U7JjDdX3ZhiwMuCl8JJ/Z6Bb1svQyKbzzrhc80uA6hLzxQUtRg==@lfdr.de
X-Gm-Message-State: AOJu0Yyk7UHCMp4/3kjU90nS9syxmR96kqQzBJt6gL8hXWIn5iIVOvWi
	j43H3pMgv0P9krDbaWrQVjq40UYd1VQrKBifvCdqgS/z1Gwf+o5C421x
X-Received: by 2002:a05:6a20:3942:b0:35e:11ff:45bd with SMTP id adf61e73a8af0-38e9f2e8df6mr4213353637.5.1769471247778;
        Mon, 26 Jan 2026 15:47:27 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FWg2ZdIrfp7hQJyXlehdDZYwDbw1Iq2wPd56M3BugTZQ=="
Received: by 2002:a05:6a00:1702:b0:7b0:cd34:78d5 with SMTP id
 d2e1a72fcca58-821ca4efba5ls5179408b3a.0.-pod-prod-06-us; Mon, 26 Jan 2026
 15:47:26 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCWJs36WwAz6MF5LH0IJoowrEybU5pDFuFPNMpbikQfwkVQEKcvQ4FPpLL1BtTSHFneg5J/Wtldsg2Q=@googlegroups.com
X-Received: by 2002:a05:6a00:bd85:b0:823:172f:4da8 with SMTP id d2e1a72fcca58-823412bc6f2mr5786108b3a.51.1769471246209;
        Mon, 26 Jan 2026 15:47:26 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1769471246; cv=pass;
        d=google.com; s=arc-20240605;
        b=DtBDrhtHJxan2F3+vMFL2O93O2odmejMYa8DKRkrCeTIbFC7G5j/1qZZs7mpg6EQzY
         TSqk9fSVkA/Gz92FYdFMlPyjJLbI8mk0igMIRG4jtcAi5yWDWs3heslJ5l+aDGL9ai19
         PR1k0R+C9LZQhrYYvREofpxU+/UKDQqF7qU479J4UxnTTk7kbKxPRfeU7AESZGbdQMVj
         ZkV5xbC/m+vnb2PfN54bOfsqpB7m5E2lKKrfDNarhPiF/CepbituaRMLbVk8B9msJIIk
         0OQYovy53tsY003UEXyqLr63iTL5TpfefPA0AmdlDEwQqWQGoJLwa3hqgxfqfDRkluDd
         yKwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X34tjfxPPMupW8WHmEJAIsWdH0Oem6uch60iKqedEdc=;
        fh=NjUTgPM1zOhY+upZ8VKuQUDOTPfBTalXjDA/h4Bi6LM=;
        b=eUTYPVDmZBiceM3w1P1Ge6k1XMnrZ3tlScwjxnLF15nnoQ7K1u5ZHR2Kvk7mG8P2Ui
         2bquMyb6ONzPeumVlPGZIxz2xkEXa3Dgvzmn7nphRHl+ICaNBtu7uHadu6oXUopXLnNX
         eXu4YHZtOE8kWyu6FZ3bRtNuMAVAyiYhjsWCTrxxjuVnehrQsAVLoK5jmAOFrMZppFpY
         frqDAyxIUi4zQh6F4MqRe9VoqOcim+2WitYNKveDfTFDgd5yWzI/kVBO0GYpMyrOXSl/
         OH1bRxPJkrQbfRqQ6aVd75RvDXKPceARFets2+FxeGXHDcMbwioNXgxommgqPL6Q32hN
         XRbg==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=STAMU9kw;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x1233.google.com (mail-dl1-x1233.google.com. [2607:f8b0:4864:20::1233])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-823181a44besi483443b3a.0.2026.01.26.15.47.26
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 26 Jan 2026 15:47:26 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::1233 as permitted sender) client-ip=2607:f8b0:4864:20::1233;
Received: by mail-dl1-x1233.google.com with SMTP id a92af1059eb24-12460a7caa2so7228647c88.1
        for <kasan-dev@googlegroups.com>; Mon, 26 Jan 2026 15:47:26 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1769471245; cv=none;
        d=google.com; s=arc-20240605;
        b=CU/nzgKdlJLR5Lu746DCGJIRXbgg+r8Qyk5DCE27oC2cLJW8ZNGEeL2hMG25/rjqnQ
         iVp3Lz9V6Yz+PqepZfvgjrF05EPRDMTiCV3HqY0VKUMo0a3wLy2v1x6eN69sMIsoiJ3k
         pU+IlivVTyuSYathnL3Nieq5MW7T77PfFBL+xjCbbWOrIPCX2UT3IW8zdraAAMMmLQdj
         gIL8jOqjIqtNB/xIgVjaBLTUjnrbbSTrwyiny0T5PdcMjulvBBsy8utksxdqnL2TLT3u
         PR0IImKQi+/llQ3UdAy4+YaA7EaoDhqjAwFXlRtnQp/juh/1w0O2HaDxk1LriSrfxSx0
         +LEA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=X34tjfxPPMupW8WHmEJAIsWdH0Oem6uch60iKqedEdc=;
        fh=NjUTgPM1zOhY+upZ8VKuQUDOTPfBTalXjDA/h4Bi6LM=;
        b=kEmejY9ZmrOyvtqD9okeKRly55i74WqixSM57iQGZbfM3M69lQMz16BEFR9VHCaYoT
         X25lYzUq4CDFSKSA8cf3WvvlknXGkcsj51XM8FYjxxfqUzr0hE3p4NcHGbCJhoer3yHn
         6xKlrVS4VrgTAiLhpap5tddiASpgZcyNfLLkzgyq9B8KqE0RTbm+PjEHeLbLnjaHL/uW
         SI9PvNG4CIn7tYku1DV8Di0FbDT6M+9eQ/HA6EALSPBzb19MFQU4MOUjBOiCcEaWRm9C
         I6PiVvXKW1ACpKWxjwCXKZqu4GljNYynB7iji8itF4OhCbWlRzun6iAXHSzNoPthnJz8
         hUoQ==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUKlnUPy3rnNLeqmU9Gs1j/GtFzgFIICECxuutKZTj0Jz6drnqHajRaEFCZtfLaWMVGc7dPHVHXe1w=@googlegroups.com
X-Gm-Gg: AZuq6aKvhd8Q90LQ0qaVuznAR0OvVwyC4+ogiq83cVxHQe9Wf7AEdRJeHGgUGGnjSqD
	rXGnadSWeRvKa9Fmk4tyMTKu2iBUdvUqCEt9Ki1vGmOJjwAAti8cKhUcZi+q1DmJRaSes+0YZ/f
	dBCtLt328cnxo+wVUHRkNlN+b8g0B4UMHYJxS5pf4Qr//dAJYxInCbLVmH7esYLmjG5IwTITu+U
	tZCXWTrMh3yTBxXxq1TlQfL6EgVg5YpVL1YEA+aR61IBcxMwRwEmnJvy59yqCcTzF60cpTx+R94
	a/7+a/TxOuRpag2yT/71WSW8cIgjsiqAvtTTLQ==
X-Received: by 2002:a05:7022:eb46:20b0:124:9e46:82fb with SMTP id
 a92af1059eb24-1249e468815mr157327c88.38.1769471245289; Mon, 26 Jan 2026
 15:47:25 -0800 (PST)
MIME-Version: 1.0
References: <20251219154418.3592607-1-elver@google.com> <20251219154418.3592607-16-elver@google.com>
 <dd65bb7b-0dac-437a-a370-38efeb4737ba@acm.org> <aXez9fSxdfu5-Boo@elver.google.com>
 <8c1bbab4-4615-4518-b773-a006d1402b8b@acm.org> <20260126213556.GQ171111@noisy.programming.kicks-ass.net>
In-Reply-To: <20260126213556.GQ171111@noisy.programming.kicks-ass.net>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 27 Jan 2026 00:46:49 +0100
X-Gm-Features: AZwV_QgcknJe0PlLV-z7bksgFQT7uSnaZ1B5QvyI9tPRocr5FzcCAIEUg9yCt-Y
Message-ID: <CANpmjNPs9CtY1w1-MqL1-CnHVFLxXoA2rbd6d2w4wfxT8AP0ew@mail.gmail.com>
Subject: Re: [PATCH v5 15/36] srcu: Support Clang's context analysis
To: Peter Zijlstra <peterz@infradead.org>
Cc: Bart Van Assche <bvanassche@acm.org>, Boqun Feng <boqun.feng@gmail.com>, 
	Ingo Molnar <mingo@kernel.org>, Will Deacon <will@kernel.org>, 
	"David S. Miller" <davem@davemloft.net>, Luc Van Oostenryck <luc.vanoostenryck@gmail.com>, 
	Chris Li <sparse@chrisli.org>, "Paul E. McKenney" <paulmck@kernel.org>, 
	Alexander Potapenko <glider@google.com>, Arnd Bergmann <arnd@arndb.de>, Christoph Hellwig <hch@lst.de>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
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
	linux-wireless@vger.kernel.org, llvm@lists.linux.dev, rcu@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=STAMU9kw;       arc=pass
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
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBD7237FQMGQEDNOSDUY];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	MIME_TRACE(0.00)[0:+];
	FREEMAIL_CC(0.00)[acm.org,gmail.com,kernel.org,davemloft.net,chrisli.org,google.com,arndb.de,lst.de,linuxfoundation.org,gondor.apana.org.au,nvidia.com,intel.com,lwn.net,joshtriplett.org,nttdata.co.jp,arm.com,efficios.com,goodmis.org,i-love.sakura.ne.jp,linutronix.de,suug.ch,redhat.com,googlegroups.com,vger.kernel.org,kvack.org,lists.linux.dev];
	TO_DN_SOME(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	HAS_REPLYTO(0.00)[elver@google.com];
	RCPT_COUNT_GT_50(0.00)[50];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_TO_DOM(0.00)[];
	NEURAL_HAM(-0.00)[-1.000];
	MISSING_XM_UA(0.00)[];
	TAGGED_RCPT(0.00)[kasan-dev,lkml];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,infradead.org:email]
X-Rspamd-Queue-Id: 9BC568E4CE
X-Rspamd-Action: no action

On Mon, 26 Jan 2026 at 22:36, Peter Zijlstra <peterz@infradead.org> wrote:
>
> On Mon, Jan 26, 2026 at 10:54:56AM -0800, Bart Van Assche wrote:
>
> > Has it ever been considered to add support in the clang compiler for a
> > variant of __must_hold() that expresses that one of two capabilities
> > must be held by the caller? I think that would remove the need to
> > annotate SRCU update-side code with __acquire_shared(ssp) and
> > __release_shared(ssp).
>
> Right, I think I've asked for logical operators like that. Although I
> think it was in the __guarded_by() clause rather than the __must_hold().
> Both || and && would be nice to have ;-)

Some attributes take multiple arguments (__must_hold does), though
__guarded_by doesn't. Yet, && can still be had with adding it multiple
times e.g. '__guarded_by(pi_lock) __guarded_by(rq->__lock)'.

Only thing that doesn't exist is ||. I think the syntax you ask for
won't fly, but I can add it to the backlog to investigate an _any
variant of these attributes. Don't hold your breath though, given the
time it takes to land all that in a released Clang version.

> Specifically, I think I asked for something like:
>
>         cpumask_t       cpus_allowed __guarded_by(pi_lock && rq->__lock)
>                                      __guarded_shared_by(pi_lock || rq->__lock);
>
>
> I think Marco's suggestion was to use 'fake' locks to mimic those
> semantics.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPs9CtY1w1-MqL1-CnHVFLxXoA2rbd6d2w4wfxT8AP0ew%40mail.gmail.com.
