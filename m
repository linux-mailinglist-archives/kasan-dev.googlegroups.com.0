Return-Path: <kasan-dev+bncBC7OBJGL2MHBBG4EXTGAMGQE4CE3DQA@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id WMgsIR0Cj2kmHQEAu9opvQ
	(envelope-from <kasan-dev+bncBC7OBJGL2MHBBG4EXTGAMGQE4CE3DQA@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 11:51:09 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83c.google.com (mail-qt1-x83c.google.com [IPv6:2607:f8b0:4864:20::83c])
	by mail.lfdr.de (Postfix) with ESMTPS id 0CD9E13540E
	for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 11:51:08 +0100 (CET)
Received: by mail-qt1-x83c.google.com with SMTP id d75a77b69052e-50341fddb89sf36155441cf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 13 Feb 2026 02:51:08 -0800 (PST)
ARC-Seal: i=3; a=rsa-sha256; t=1770979867; cv=pass;
        d=google.com; s=arc-20240605;
        b=QAjaWzPeEjNR+ZqObHxJuClBCnKs2nH2LweSN5du4y5IVFMSMgngeXcmBLgBVM7YLF
         R2vGIa0qzwOPLw6Dlb+sGXRKEhkVbsCvauGzO2gplzWc2rQjE8EJbTZvyxv8PpaWfQpm
         kzoUNj7M6+fC7VHCY8R+lvABmduLSamDktCT/nuFySaJ7uFIgwk4IKplJ1BqECRy0BXB
         KqPBA7QZRz0HxmcNfhAE5w0G6Nb4+BNe4myiDyFvWhofy+j3zXDLvkpaiWQL+S2JkMJe
         i2oSyPrJ3eDwXEF9+7/xIDaz37FBfPCcUTB2WWQXJIlkC9bcFWYVCz2h+k1NwTLyrRJS
         npzw==
ARC-Message-Signature: i=3; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+XTX7/sKLga+zoOz4gSWosPTeP847KBPtWSkjWJjMdQ=;
        fh=Z0O7ndVwvrCZ+trtJsgBw//m8vyNmxkDAI95ssKImhY=;
        b=cjU7e80LWjV8GoTgAgjNEdPtUj2ppD6IeEEZ2G8842pMsSKr3hWOipkQw4gLeHMul3
         6zYViv2pa5PgBU3JFGitdHWcFHTX6sIRK/PBZPdLQ6hZLELSQvCcVKjHDLaljB9Fjuec
         uytgmRUaT67CVICIYAD9lfZjP7etSL0hWj+dVbqC3MU1N/ZZ+P0ARHy6YoIxqNOt9SGk
         qqNAIFhddFfotkD/E91YfRj932swsUwa04XSM4ECAknSkBowZaHq6sacZOOnlMCrBYbO
         +HsCNlQpXGZxUIc+bBqhZEjr0c8IsHcgrOPe9B/TvbbGNQrnjobRSDSF+bquC0OPb6Rp
         qr0Q==;
        darn=lfdr.de
ARC-Authentication-Results: i=3; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wzlt+Y2u;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1770979867; x=1771584667; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=+XTX7/sKLga+zoOz4gSWosPTeP847KBPtWSkjWJjMdQ=;
        b=i+1zHrhyPgIRq2TLuyDE2zAl9ejdVGvtTGHogcFAZ3HN1rt8e+O7b9/jHn1cNhjc8z
         C0IQHAeqpHTuPAXpaaOJA8OB/LJsbrGc8Oek/pvVAfkCifJbGnLH78yZfBPwtCoOEXP7
         69Ewd9/29tbYH7fI3z0Otv1KYZWk1/UklTHzsiJuCf5pA3ClpRs9SPIXmM0SE8RyDp+m
         Lc3BweWfAZQBmQ4FDHv7uydOuwxqGYTsg0H38hRCutdmS7MTa81wRYasnsVS9AKvYCah
         icTAYdnc3IMneFBaYKOYiMbBe9ShUO2Kq3BsVYSLTnRr/9B+Y7n6Ot8P6xnGs4VR6vl1
         Awcg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1770979867; x=1771584667;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:x-gm-gg
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=+XTX7/sKLga+zoOz4gSWosPTeP847KBPtWSkjWJjMdQ=;
        b=kGDX/nLsb7kzexUH2/OSUJHKUytpI1hQCiWp3qSdJL3elVGgMVNXbTbMMiwORWjK1g
         4TQHhFXMOTrc+Bx+/uwqkXFY4AbmoJJNARucobrWinezVx+FhdqVSu/pCq7wNDghidz3
         ptyoyxXq/shs9qP2keYGAo3AUbFUBU3Xol8PZ4AUwzJw6HCqnUZdL77YyJfWFqdnzZOi
         r//bDYU9Z1wk0ft2Of7cP0Udr4MsuIukGrPgKjlKhrx4GpdiW+HMhbILprvsRGGylFOB
         Q3sdtyzsq2IP1QvMQWUpdTEnWH+/aHhWANg8W3Wg8Yk/a9jDQdDqJdKAo6dD5petCTcj
         XaMw==
X-Forwarded-Encrypted: i=3; AJvYcCXFqFf/CJvh0wOJZnnQYtXWjIJ/0vEqt4LSskdEQeukONbKHL1KIhiRk/sbQXFD+M8NPc+PyQ==@lfdr.de
X-Gm-Message-State: AOJu0YyFdP+kJ4guUwMEstULt6iaSFbwWBpOauCzyNKtp11yN6y69ZRb
	D2tbBRJxgV8rS/d8facS3pgLeJgvhUm0p3e9zBsAzW87PSqG1qYTKykC
X-Received: by 2002:a05:622a:48b:b0:501:4a4a:c24e with SMTP id d75a77b69052e-506a82a4a16mr14473651cf.25.1770979867304;
        Fri, 13 Feb 2026 02:51:07 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+FcUWVEw+erdGEBR5PNeGhOUChe8Blq3RjhNhwVrW+kYQ=="
Received: by 2002:ac8:5f11:0:b0:4ed:9424:fa31 with SMTP id d75a77b69052e-506a8ef303els5805431cf.2.-pod-prod-01-us;
 Fri, 13 Feb 2026 02:51:06 -0800 (PST)
X-Forwarded-Encrypted: i=3; AJvYcCUH3zO3JJBhSJc6kw16BkcGk9uoaT/PzuAykDK/kLnfTdUlSILZPRcn6KbSyDak5/76Gy7tP7KosDw=@googlegroups.com
X-Received: by 2002:a05:622a:102:b0:4ee:18e7:c4de with SMTP id d75a77b69052e-506a839d236mr17796131cf.78.1770979866411;
        Fri, 13 Feb 2026 02:51:06 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1770979866; cv=pass;
        d=google.com; s=arc-20240605;
        b=hNfD1258KXdomTuskj9Iv8yVvBbHgz56wBYqlykAXBNOX2FJTzT358tIn+EDUjpUpS
         d+wp2hSZ1W+G9f+XlE9moh4XdWhAj4S9EMCQH/ZizqQuV96iOdgGzYxt12BUVn2/+IGq
         YJ8CT24vpum1aEkcrr6mF9DlMy8vcKY/AnRfrze0es21qrT92OvNU5GKqQo0AE4ty+Mx
         uafmCTpI+WnzAAJt3sRF6SqgKmXVeclZ3aGYDuNlas7IMrg3F4gz14NQKcNnBT/bd9I9
         GdTiJZRGZ9tC0we3Y9H3mzku0E2I3bx29e0WhpVzVzjvoHnM4hx/pJwqViFSIgRwnRvT
         Smlw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H2yjc4HwnZnDfH81aOY9V+Nb7nZlWZ+t7zlqHmmWMvI=;
        fh=ttt3vrGXKb55NTqSqPSzmULV0veRSZ1swq6BK18T/o4=;
        b=cFF/yTz09WQ2tlUMj31eIs5jIRVxXD4vXSq7hHq8jEoQiRbCSIgoKCtXYFBaf8mTN+
         2Ik94CVG3w1BMqtD3OmAldvqpOJQ+rH6Mu3H7MsZ9qd5sZfqfrESPX/q/5hwbqewOPA7
         g2PNnPRxHMe/UrgadZB7o05SUbnxOZT+WUefBZ9xvnP4iuT4Gu0SziwbfvP/uoHQ9gTE
         PJx7vuSNCfb7wNjGtUel47JRvAar9gzfNwWTBDBy0UMdZmZc8REa30Tvlhgau5msfU1e
         I/Q6zs2TtcY1EqGbdN+NnXiHMxcuuY9yJHT78NpeTt5ElKeO+F2opiMlZPp9ucKDuoMv
         ogjw==;
        dara=google.com
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=Wzlt+Y2u;
       arc=pass (i=1);
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-dl1-x122e.google.com (mail-dl1-x122e.google.com. [2607:f8b0:4864:20::122e])
        by gmr-mx.google.com with ESMTPS id d75a77b69052e-506849f2bdfsi2512391cf.2.2026.02.13.02.51.06
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 13 Feb 2026 02:51:06 -0800 (PST)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::122e as permitted sender) client-ip=2607:f8b0:4864:20::122e;
Received: by mail-dl1-x122e.google.com with SMTP id a92af1059eb24-12732e6a123so532005c88.1
        for <kasan-dev@googlegroups.com>; Fri, 13 Feb 2026 02:51:06 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1770979865; cv=none;
        d=google.com; s=arc-20240605;
        b=EPye0s8sXX5NK+8DfTm9eli3N4U9T5mrHC1x4rmVqOxW8QI3Nxz/RbGh85EKk/kzr4
         9wGSt93dkuSX4k5BTi9/YIBuWLe9kXkOYKY5x8XClDqh7ahKFgkq4TmC7G5JND0VII1W
         SXNaFXa1Jk0/8P8qLX/N6SI9soxxK+SQog+KGk1iMkVfo/a+SsOrrqWN1iKY4PlGAGFv
         d0eEmmUtD8VBrVFY1a9N68lPWwzpZU1IPbQyZFMlsiQaBhg7oBXXCgYwSWoahLzem3YA
         E/SZeY+VF2d+T2qQ26zt35CW4Zrk29fbmQ3QEGEtqc6iRjRODlz09Wce2t4WCLYNpMcb
         6qrg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=H2yjc4HwnZnDfH81aOY9V+Nb7nZlWZ+t7zlqHmmWMvI=;
        fh=ttt3vrGXKb55NTqSqPSzmULV0veRSZ1swq6BK18T/o4=;
        b=bfraB9lqf21XL8dp0kbuMnkeKpcFN/7EhSJdpB7ZR70tMp+J1L3Y4cfe6qtN/jMjte
         LZn8DwjC9bMxxuCCpKa3Crnuv1pIHSOTVqbbhYqel5hZqPEH/HcRu9tEdmSq+4h+fWb9
         ScbZLt3+dyuGAVPwzKB8MorRNNMkordHyBr5qXFSLiD535dsCQVe6ALJQm90uzVSmfqU
         pfvh/ZdKRhKCbdoOYqj2/CLxDJOih0q+ZvhB++vFmTxoWKaYg6qdhRlGrL0A2b/x/+MD
         rLf0hvvBaNEYoRsG1E9KLFIb0rr5qagin6tag1rLmFf1bYMQpnfxuAY74kNXD6L9xRd+
         1+8A==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com; arc=none
X-Forwarded-Encrypted: i=1; AJvYcCUXIuoChk07OzNdfq13bSVbcDa8RMmtSMD1UgnK65rQkUsZ9+7Mp7pzIe8GPcYNealy3JCx3+bCX08=@googlegroups.com
X-Gm-Gg: AZuq6aL47kuhyoIqlzhR7bS1ejTCnu7DYTa036rnsPY2GbVPj3YVf2b76UtWu5ofkJZ
	ZY7wqJk89nw/FkTYe8bljO95yLy9KRNhUCJCls+fLr88jRQ10uoh0BvlCUykDYmG+6sEJp0zW0f
	r3pezwSWB9MH+QPa12t/RP9CQkH+mdD4sHGd+1PZpAr5mtn6fF+fW4FCDY/kZS9nHfkeSX5DKKA
	bjqeMQn7viA8vFgOP2LhXIAjH1THwnncREMPFHewcz6LuPMhe3pEto82hFjCCtubfS5TpACE2qB
	aWHSPCPUPoCtAh5eTbIYvNY7TuDYPmsgTiF+ReJFC2n//dv3Fw==
X-Received: by 2002:a05:7022:403:b0:119:e569:fbb2 with SMTP id
 a92af1059eb24-1273ae47f17mr592920c88.33.1770979865034; Fri, 13 Feb 2026
 02:51:05 -0800 (PST)
MIME-Version: 1.0
References: <20260213095410.1862978-1-glider@google.com>
In-Reply-To: <20260213095410.1862978-1-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 13 Feb 2026 11:50:28 +0100
X-Gm-Features: AZwV_Qj3kSyotLTHtMF94eaTev9fGUyX13rb1GtRDWyCVZcl4zIsPhmkTtg7Z6o
Message-ID: <CANpmjNPJV-aQKnQ7Mtr6e8_12UR3C2S3abJx_ePFWmS1WV_UVg@mail.gmail.com>
Subject: Re: [PATCH v1] mm/kfence: disable KFENCE upon KASAN HW tags enablement
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, mark.rutland@arm.com, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, kasan-dev@googlegroups.com, pimyn@google.com, 
	Andrey Konovalov <andreyknvl@gmail.com>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, 
	Dmitry Vyukov <dvyukov@google.com>, 
	Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>, Greg KH <gregkh@linuxfoundation.org>, 
	Kees Cook <kees@kernel.org>, stable@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=Wzlt+Y2u;       arc=pass
 (i=1);       spf=pass (google.com: domain of elver@google.com designates
 2607:f8b0:4864:20::122e as permitted sender) smtp.mailfrom=elver@google.com;
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
	MAILLIST(-0.20)[googlegroups];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	TO_DN_SOME(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	TAGGED_FROM(0.00)[bncBC7OBJGL2MHBBG4EXTGAMGQE4CE3DQA];
	RCPT_COUNT_TWELVE(0.00)[14];
	RCVD_COUNT_THREE(0.00)[4];
	REPLYTO_DOM_EQ_TO_DOM(0.00)[];
	MIME_TRACE(0.00)[0:+];
	FROM_HAS_DN(0.00)[];
	FREEMAIL_CC(0.00)[linux-foundation.org,arm.com,kvack.org,vger.kernel.org,googlegroups.com,google.com,gmail.com,tugraz.at,linuxfoundation.org,kernel.org];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	TAGGED_RCPT(0.00)[kasan-dev];
	FROM_EQ_ENVFROM(0.00)[];
	REPLYTO_DOM_NEQ_FROM_DOM(0.00)[];
	MISSING_XM_UA(0.00)[];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	HAS_REPLYTO(0.00)[elver@google.com];
	DBL_BLOCKED_OPENRESOLVER(0.00)[mail.gmail.com:mid,googlegroups.com:email,googlegroups.com:dkim,linux-foundation.org:email,linuxfoundation.org:email]
X-Rspamd-Queue-Id: 0CD9E13540E
X-Rspamd-Action: no action

On Fri, 13 Feb 2026 at 10:54, Alexander Potapenko <glider@google.com> wrote:
>
> KFENCE does not currently support KASAN hardware tags. As a result, the
> two features are incompatible when enabled simultaneously.
>
> Given that MTE provides deterministic protection and KFENCE is a
> sampling-based debugging tool, prioritize the stronger hardware
> protections. Disable KFENCE initialization and free the pre-allocated
> pool if KASAN hardware tags are detected to ensure the system maintains
> the security guarantees provided by MTE.
>
> Cc: Andrew Morton <akpm@linux-foundation.org>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Dmitry Vyukov <dvyukov@google.com>
> Cc: Ernesto Martinez Garcia <ernesto.martinezgarcia@tugraz.at>
> Cc: Greg KH <gregkh@linuxfoundation.org>
> Cc: Kees Cook <kees@kernel.org>
> Cc: <stable@vger.kernel.org>
> Fixes: 0ce20dd84089 ("mm: add Kernel Electric-Fence infrastructure")
> Suggested-by: Marco Elver <elver@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Reviewed-by: Marco Elver <elver@google.com>

Just double-checking this is explicitly ok: If this is being skipped
enablement at boot, a user is still free to do 'echo 123 >
/sys/module/kfence/parameters/sample_interval' to re-enable KFENCE? In
my opinion, this should be allowed.

Thanks!

> ---
>  mm/kfence/core.c | 15 +++++++++++++++
>  1 file changed, 15 insertions(+)
>
> diff --git a/mm/kfence/core.c b/mm/kfence/core.c
> index 4f79ec7207525..71f87072baf9b 100644
> --- a/mm/kfence/core.c
> +++ b/mm/kfence/core.c
> @@ -13,6 +13,7 @@
>  #include <linux/hash.h>
>  #include <linux/irq_work.h>
>  #include <linux/jhash.h>
> +#include <linux/kasan-enabled.h>
>  #include <linux/kcsan-checks.h>
>  #include <linux/kfence.h>
>  #include <linux/kmemleak.h>
> @@ -911,6 +912,20 @@ void __init kfence_alloc_pool_and_metadata(void)
>         if (!kfence_sample_interval)
>                 return;
>
> +       /*
> +        * If KASAN hardware tags are enabled, disable KFENCE, because it
> +        * does not support MTE yet.
> +        */
> +       if (kasan_hw_tags_enabled()) {
> +               pr_info("disabled as KASAN HW tags are enabled\n");
> +               if (__kfence_pool) {
> +                       memblock_free(__kfence_pool, KFENCE_POOL_SIZE);
> +                       __kfence_pool = NULL;
> +               }
> +               kfence_sample_interval = 0;
> +               return;
> +       }
> +
>         /*
>          * If the pool has already been initialized by arch, there is no need to
>          * re-allocate the memory pool.
> --
> 2.53.0.273.g2a3d683680-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPJV-aQKnQ7Mtr6e8_12UR3C2S3abJx_ePFWmS1WV_UVg%40mail.gmail.com.
