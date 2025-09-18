Return-Path: <kasan-dev+bncBDUNBGN3R4KRB5NHWDDAMGQEV7LBZSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33c.google.com (mail-wm1-x33c.google.com [IPv6:2a00:1450:4864:20::33c])
	by mail.lfdr.de (Postfix) with ESMTPS id 6A3CAB851B2
	for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 16:15:19 +0200 (CEST)
Received: by mail-wm1-x33c.google.com with SMTP id 5b1f17b1804b1-45df609b181sf11223855e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 18 Sep 2025 07:15:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1758204919; cv=pass;
        d=google.com; s=arc-20240605;
        b=XIQPEPY0S5OWU+R8uvYgz/wK81bQ3C/0FXi7acMkoggNY3R72RYjxHboLWcF+HADUj
         ADY6gVb8UHmJQLDJKITrm4PRwOBexHXzTgl3Awzv2kHcaLCROjqlcdyCkn8XPQwLvfEu
         /D8ocOPvun2Mddc65DwD4fP2oqeK2kKQgNaA8mw0tjip/rv9Y6zVY9KZAdKICXHQnTlH
         K57obypTOmysZSBm+0MV4JY8cWv7KI01oZP+L6FFLbW5fMqNCH4yDSsMyOyRqhOB9BwJ
         UwrfZ/snoN1cxezQCaetI0id7qJBK49BLRdYfcWfb1fQHEBDdnU97aOT/vnaHZzdfLlO
         4XQw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:dkim-signature;
        bh=9qpllMZqv6UQvdkJPrfSgFWnbBwaExRx3odIIIpEnIw=;
        fh=f1iuVrDT/O3TMWUb0Xfr44bhGth6+zUpVuOhRuGYAxc=;
        b=c8uiLibr6iJWXzK1s9/aLg1kjInwuK7Unuk/MucXLG5iBJwQNN4VWWif0y2V3hHNar
         FDUGNvIvY8lb/+3fvuC5jEMRGnOVRO2kC278bVVWA/qFlKUONxS6Rrg+MGkOiOn7uH9c
         bsZljSREfu7sfMs5LFW6TIfIWyBl5Xqwx0tbPBNMUQPADjxQRDSQhxhu1z1KUDd1YmAk
         SQq/TwkLqrr1SQbB0QEEvWufvFT6+mtnPKJfXlhsBHu+31ZE4ZuyEASzI27OVGwAVoVo
         Qs4BJa2/GuqatCPQT5tfTmoUlQoxKisAdjcJolL9pdT3OgZXxeolD8djvYl+mbqIJcCR
         genw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1758204919; x=1758809719; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:user-agent:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=9qpllMZqv6UQvdkJPrfSgFWnbBwaExRx3odIIIpEnIw=;
        b=xXvXTyHIfJYYFOOcpt9+dm82Og6vIeJmZfLQ9k4zo6jOFyMl/ohAl1wcfUbs8hhiNw
         knM8RwX5EXuvglsKAUwGWpQ4r48CQeih3v8USgDO1Djwid8ZxI49IA3VeJQV3ffEcnO0
         f7r9zliobTH1rhSZBP6zFE0UUCYGowGtXcDvTdkPg/H1/ccMksEZBIvKfy20PvoIVUAH
         tlTRA7hJMkFWseDNjlOvrNQS45VpDUK47utYoO0wH1n8BtTQKj0d6jOZBMxrE9VeT0Rl
         SRaxs/w46iUdAKPC2gq9t9gNMUHOJDZcofXkBvphVjee8UfobFWjmuwSAVQsae4jXBCg
         +W1w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1758204919; x=1758809719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:user-agent
         :in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:x-beenthere:x-gm-message-state:sender:from
         :to:cc:subject:date:message-id:reply-to;
        bh=9qpllMZqv6UQvdkJPrfSgFWnbBwaExRx3odIIIpEnIw=;
        b=Gvc28rR370bypAqTIpy3a22IGgKqdUIDwyPO5VcROHVLkDDd9FdflfT4jbIoG8gUQO
         0U1J7yl0wCXVIOpWv3W87WQrRdFkH9eEwGCBk2S5raVbVBvFpVcwmUcL+Agqw4PCLR/S
         3U/3XRtrZ7dwHw9OYLdq2nJRX0wxIEL2dLrUg1RkJh0HLkBDIJFUc5RvUmjIBNRhUwdp
         L+hJ1YVHDsUQZr0lHBeA/0op+Ep7kd6z24SxZ+yDRwLvq4c4wjCtHUZyAMrTTHkzPuoj
         zbLe2iOKYbnqv7i2sMohsZcOpUPAIZp6gy804uYYDouuzkt+4+sWijL0zoidGgCS3kV1
         Qxcw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWGzogvw681JyW455Sntcp/4PQD5C1sNR+I8EsCZP5SV4k8RNjnblx0t8gTSIk9d09l37EVjQ==@lfdr.de
X-Gm-Message-State: AOJu0YxdGH1Liq3uJOnVi30JzQrhlbRWkMaLqbO6oriqGteYsENSfb0C
	tn5u02PAo9y9dH2b2HooYn4NmzSyQDFwYrQySzpD+Wm3EMznjLrbrb6O
X-Google-Smtp-Source: AGHT+IFd4xn0jnlvlvrJK3QjqP6j6rZnGjbX+ULHy4fySre6ofxkr1Xs7GqmIErmAjKDH5Ki+OcHlg==
X-Received: by 2002:a05:6000:4387:b0:3ec:c50c:715d with SMTP id ffacd0b85a97d-3ecdf9babadmr5854471f8f.23.1758204918636;
        Thu, 18 Sep 2025 07:15:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=ARHlJd5pGi+NVJY5Qc7o1vz0w3TZxz5NLhFYIfvuMBjjKWIPMg==
Received: by 2002:a05:6000:1aca:b0:3e1:d1b0:66c9 with SMTP id
 ffacd0b85a97d-3ee106b0ccbls583399f8f.1.-pod-prod-09-eu; Thu, 18 Sep 2025
 07:15:15 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCW64hnx0OratjMLeUMAEUZL3X1MHQ247uxISbGtE0UxUYaFKgXS213Jj0mFamTbTM5W1n9ahyK2Ei0=@googlegroups.com
X-Received: by 2002:a05:6000:24c5:b0:3e8:b4cb:c3a0 with SMTP id ffacd0b85a97d-3ecdf9afe4amr4697245f8f.8.1758204915685;
        Thu, 18 Sep 2025 07:15:15 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1758204915; cv=none;
        d=google.com; s=arc-20240605;
        b=QwU4HK+2Hirqrz1zuxXDuioeD+2e3vRCHD+Rog3dx8L/QBkmp7a5+3IPrWNM1I7Ivy
         5ygyxni6Zw0ZDOXyEggP/30DlEku10vLMJltYQEKS+4g7VDkRGT0wX7urIt5Bm/2S8PX
         SYK93/wwKqm6eqbjUATcJTKghpODP2T0BqKNaB7MwFW5bi/b/KEzP/sViiBw5ByHrJOv
         QCeE6DZuECaBx/iiraC9d3lANWZSfqSWkiUxxIhkfVAqld0XNxn7DqPAM7pK5yok71vS
         aGmobymvQvmgmBrjNxz7YtyOoTxAmFWUnyj6nvcc1blXuSEvtmMJuFSAgRYeCuiA4BtL
         Ziig==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=user-agent:in-reply-to:content-disposition:mime-version:references
         :message-id:subject:cc:to:from:date;
        bh=khXb/ArQuyu0wy6xtQhmAnwTxUmi7GFWHE031JjnAKA=;
        fh=Yv+hB4RzIUAN9bF/5iTIoZQdRfiddYhsU3Qy4cJkSS8=;
        b=ThxAtFC4t+RONRC+PHOOpshyDb4dgy6p9EUC7J/uhunFE65Pr/ZuMusZo3gfHcb6pF
         v7tOWEF/cMt4E3JST+6L+oUgLvtIdJerqWmNSiEO5U02sfJ1pbL94Os+thsGN5ruIage
         tx5EBgFkxhuiLJsQgL+tlgkPx93BVorFNDLtIBuk728MkpcUNpb1xkhMdUez7PQs0Mzh
         12jlk8vwZl+VH9pLWrYZiL7W9bXrcUiRvn4HmfHC8/Ftf40ZENsW5i2WHS33niWbXR9u
         RHT90fgBoKLfyHCRyUAOTDk/+selln90LzS8dgNJ/vlQ3x3T5nlxc3wzQ4pjR/tHB9z1
         SHKg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) smtp.mailfrom=hch@lst.de;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
Received: from verein.lst.de (verein.lst.de. [213.95.11.211])
        by gmr-mx.google.com with ESMTPS id ffacd0b85a97d-3edff885cf2si50517f8f.0.2025.09.18.07.15.15
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 18 Sep 2025 07:15:15 -0700 (PDT)
Received-SPF: pass (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted sender) client-ip=213.95.11.211;
Received: by verein.lst.de (Postfix, from userid 2407)
	id 3F714227A88; Thu, 18 Sep 2025 16:15:11 +0200 (CEST)
Date: Thu, 18 Sep 2025 16:15:11 +0200
From: Christoph Hellwig <hch@lst.de>
To: Marco Elver <elver@google.com>
Cc: Peter Zijlstra <peterz@infradead.org>,
	Boqun Feng <boqun.feng@gmail.com>, Ingo Molnar <mingo@kernel.org>,
	Will Deacon <will@kernel.org>,
	"David S. Miller" <davem@davemloft.net>,
	Luc Van Oostenryck <luc.vanoostenryck@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Alexander Potapenko <glider@google.com>,
	Arnd Bergmann <arnd@arndb.de>, Bart Van Assche <bvanassche@acm.org>,
	Bill Wendling <morbo@google.com>, Christoph Hellwig <hch@lst.de>,
	Dmitry Vyukov <dvyukov@google.com>,
	Eric Dumazet <edumazet@google.com>,
	Frederic Weisbecker <frederic@kernel.org>,
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>,
	Herbert Xu <herbert@gondor.apana.org.au>,
	Ian Rogers <irogers@google.com>, Jann Horn <jannh@google.com>,
	Joel Fernandes <joelagnelf@nvidia.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Josh Triplett <josh@joshtriplett.org>,
	Justin Stitt <justinstitt@google.com>, Kees Cook <kees@kernel.org>,
	Kentaro Takeda <takedakn@nttdata.co.jp>,
	Lukas Bulwahn <lukas.bulwahn@gmail.com>,
	Mark Rutland <mark.rutland@arm.com>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Miguel Ojeda <ojeda@kernel.org>,
	Nathan Chancellor <nathan@kernel.org>,
	Neeraj Upadhyay <neeraj.upadhyay@kernel.org>,
	Nick Desaulniers <nick.desaulniers+lkml@gmail.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>,
	Thomas Gleixner <tglx@linutronix.de>, Thomas Graf <tgraf@suug.ch>,
	Uladzislau Rezki <urezki@gmail.com>,
	Waiman Long <longman@redhat.com>, kasan-dev@googlegroups.com,
	linux-crypto@vger.kernel.org, linux-doc@vger.kernel.org,
	linux-kbuild@vger.kernel.org, linux-kernel@vger.kernel.org,
	linux-mm@kvack.org, linux-security-module@vger.kernel.org,
	linux-sparse@vger.kernel.org, llvm@lists.linux.dev,
	rcu@vger.kernel.org
Subject: Re: [PATCH v3 00/35] Compiler-Based Capability- and
 Locking-Analysis
Message-ID: <20250918141511.GA30263@lst.de>
References: <20250918140451.1289454-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250918140451.1289454-1-elver@google.com>
User-Agent: Mutt/1.5.17 (2007-11-01)
X-Original-Sender: hch@lst.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of hch@lst.de designates 213.95.11.211 as permitted
 sender) smtp.mailfrom=hch@lst.de;       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=lst.de
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

On Thu, Sep 18, 2025 at 03:59:11PM +0200, Marco Elver wrote:
> A Clang version that supports `-Wthread-safety-pointer` and the new
> alias-analysis of capability pointers is required (from this version
> onwards):
> 
> 	https://github.com/llvm/llvm-project/commit/b4c98fcbe1504841203e610c351a3227f36c92a4 [3]

There's no chance to make say x86 pre-built binaries for that available?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20250918141511.GA30263%40lst.de.
