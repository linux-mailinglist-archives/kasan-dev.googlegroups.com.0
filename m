Return-Path: <kasan-dev+bncBDE45GUIXYNRBROX3HDQMGQEFT3E2FY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-x113d.google.com (mail-yw1-x113d.google.com [IPv6:2607:f8b0:4864:20::113d])
	by mail.lfdr.de (Postfix) with ESMTPS id 6F26CBF2994
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 19:05:11 +0200 (CEST)
Received: by mail-yw1-x113d.google.com with SMTP id 00721157ae682-78420037133sf30063337b3.3
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Oct 2025 10:05:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1760979910; cv=pass;
        d=google.com; s=arc-20240605;
        b=hAudRU3tVoUIhr390WVORVGV7cj8DSyHvJsq/XdXTr86B7wzIGxCxHCH5jvreBZ5Ul
         Tkovv4+sYKOLLUBRYDwROtq4BurY91s0kOjpALMi3aoXLmTaQ3nNGdyHZ/TM24TeYyNh
         tWVoiB1AWYPEMhD3nnaF4O8Y3GFZqe+gJRyz8zIZG/SJhSS5EVBVQQ5e2SgPLM0Ix9H6
         cLneq9aPIrGIbWvoG52bRM+u/iTELiIMZv276RQ+bFX4xBHbc/djAv26FmQmf9NWGZ6q
         hZecq0EyFAY01BP1Q7VVqf257DaNczMyKgyEFiSaStqWCM31hb5CxRVoP0tJa4Lc9wiW
         kEMQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:user-agent
         :references:in-reply-to:subject:cc:to:from:message-id:date
         :dkim-signature;
        bh=DFF6U+qr5nsGxGQMKxSBrvfvGRfGg2lqHkj+wr9R3ds=;
        fh=1pkDXuCLLnvCzCR7zrHcFzyS1cOzRbbPhL5JLDSrfxg=;
        b=fK0c9sN8hTb5KGVNz79NcciwEkMsgqDKMgjgcvPzBgRqBDtnhiS2nYImGjkDwOdGbh
         ND90YvaAInc+xdWw8XNVX3vtg7UXKF47piafoMYzgim40xkClRRt5frxPPZj9JlfyS2F
         9skU+kQ6mXlbHKuWbbPQiKK0K2G8MX4RlAyEkwIBxFMwNCYva6tz9OTD0DXDLHGWX2xW
         v88eYv6R7f6xc7D/wjwh0oYU+XVBp2peH0ww6CneiN+sHNaXIPKV/1N3z+2sAqpbpcWu
         s1mHdDNZeRwEbqSCeX23UNUXaeI1yPwpOXf8i3oXchFuuaTYLUa+l+cSUsFj6TOoH1cR
         vR3g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HlLf+uu1;
       spf=pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1760979910; x=1761584710; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=DFF6U+qr5nsGxGQMKxSBrvfvGRfGg2lqHkj+wr9R3ds=;
        b=gXIRmDWKSvf85leshlTWfm5PiTlAO+DraVtCynjvQGm2T1S69EZ7DVQUZEy6254uI9
         7shl1ORNSibKhZ5tHk+lZzXpD23omlOmMhFy9q/K9TbL0oSvq9pKAxrwenalpB7GgVRE
         Kxmnek/VEo7TBxJZUQooeC7rY7zMHeilTpXA0pi/fWRqBNY7U1u678i6dZy/mPsSsy2W
         TkWbsYF9tszMYTGPxFP18hXe/juQ//UZRDc8KWCfIgvJvl21U/PdtBTevDzkAoKl/kZ2
         qj/QqnkQ9zJW7OexFYB9EssSC+EAzIBPBDKoMg6eCNdoVIRaqK00sUdPnmA6aHqFzx4P
         EVBQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1760979910; x=1761584710;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :user-agent:references:in-reply-to:subject:cc:to:from:message-id
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=DFF6U+qr5nsGxGQMKxSBrvfvGRfGg2lqHkj+wr9R3ds=;
        b=B7SQ3ny0leWtwq90IZOTxWf8JfD2cwtu4JmeDqEqwGquzC2BroYvmu9CsAMJe73Pgx
         Tm2EKVoUSbS2DSdXbxo2+4l4Vku6npJonCj59R4vaxC1CMcZT+PDBKShXSvYn1ZWDAIu
         zvcwTemH8mrVQECJk4zbkCcLmtHBVTKp6GAEvrbw74oUPPRVf4jezqf0HDOFgVJwDIJv
         2p7C9py+PPqZBcV1wjQrMv2mRtjlfYZrNSXScgXockuHJADAyYfWj9pvdhuGVjbAfWAw
         +hpJdzBsAju+6gOATh5DbFIOb0aR2fl/qh+1ozji8WKdLzCTmiGqBw56O88BwZJMDkhf
         SM2g==
X-Forwarded-Encrypted: i=2; AJvYcCUy99sIK0o1nMm2Sva7rgCJguNZb8VJaqwZ+gujHFCX0gcqAE9sbCqc/l5ryhciFKTThhb9kA==@lfdr.de
X-Gm-Message-State: AOJu0Yxu/TSDoOboM9jQeha2eRdOCpYlr8K8htuFv5/ivF6aS7bTI3qs
	1GWpDSWg3wUQi18Yb5UDMIruQ72w+k6r/QrOZXeSGZtzZJd/YzwVZ+7C
X-Google-Smtp-Source: AGHT+IGRkon3UU2ZxjHfRTw35VjA4sdjlqomjB/Q16ViWL9NgKu+l3UTxzBSnPoPO5GZtXWo+PpoqA==
X-Received: by 2002:a05:690e:1483:b0:63e:29ad:ad8 with SMTP id 956f58d0204a3-63e29ad0e51mr5789299d50.25.1760979909650;
        Mon, 20 Oct 2025 10:05:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h="ARHlJd5Bi3Kp9vjwnGDRYi20Q3rJvLL9QfedvGb8QSunFzavaw=="
Received: by 2002:a53:b101:0:b0:63c:df86:2aa7 with SMTP id 956f58d0204a3-63e0d726d4fls4023943d50.1.-pod-prod-09-us;
 Mon, 20 Oct 2025 10:05:07 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWGyplHzK+Kr4QMZNfp4XCNBwE6KKkdqgvDlxh+nqqyXS69aguO/UcN8XL0AyRIl4AK9YMDXON5sVo=@googlegroups.com
X-Received: by 2002:a05:690e:150a:b0:63c:f478:a392 with SMTP id 956f58d0204a3-63e160e99a1mr11083619d50.6.1760979907156;
        Mon, 20 Oct 2025 10:05:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1760979907; cv=none;
        d=google.com; s=arc-20240605;
        b=dk6uB4BKFawSUeffT8R5WoHlhEJ445JZ8rA+ZVh+MAHrxgvrVU40/2885dVMwKBaJI
         Vn6y9QqvXDmai9vzHjJcjOCYjCU+4GmDDOKj8rxi7h481/jRywHY6zLxE7tBkkxJW9IB
         +oRGdtCNqHLtriKRm+0wfEcsm9EMkSdtV1xtxPyxUzp2Ar1gOlweRnnNBSCgsbedSmlA
         xzuNdpCxfVwKaFpw0gZhYGfqt9Ij3l41wbb0YEoA2fiTP8d7VyHLr9q5W/pavdb9wGH8
         31PmvzxZikldZR/r7jdRuMHPgm7nQLbQ22IMAi80NurC6gJF7yrDSTtX6Uj8G+/4ch/J
         NDYg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:user-agent:references:in-reply-to:subject:cc:to:from
         :message-id:date:dkim-signature;
        bh=5Mda8oOOpYCD565rSyu3DIf2XuqcwsaLNOoOyBWIStU=;
        fh=2I6TuXMYcRNNrCjn1jRpbuD9zai3uxO6fbJLk4U/BhY=;
        b=bByhvHHH/L+2y/cDND01MSJtjhzIRLthTgIAcNciBPxNK8o90bYjlamO2If+Dsd3U7
         78JZKgnUuTSWt5dOnp9Jd8SXN2wkqRtEvVRvHrYjoaXCYNvanszKMswtPN38RFKa1z1s
         008k1ayOFp2TzCJw9lh5YfvVU4iLl1yArKCpBL9y1rBA/V7an66GGBG5rfv07RdCO2kk
         xpGZUejLClTXvEAVkj5MY+o/dLHD/hyoWFvPjMn2NlDrIQ6R+CqaDqrjqGllv4LXIV3x
         Mg4TqZq+c6gpLqYrfNjtFnPexNG36hVluBoZ+WDfulFv9oAxedqunfOfSIKbgrQXG+nu
         RLyw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=HlLf+uu1;
       spf=pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) smtp.mailfrom=maz@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from sea.source.kernel.org (sea.source.kernel.org. [172.234.252.31])
        by gmr-mx.google.com with ESMTPS id 956f58d0204a3-63e267ec3d4si367922d50.4.2025.10.20.10.05.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 20 Oct 2025 10:05:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted sender) client-ip=172.234.252.31;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sea.source.kernel.org (Postfix) with ESMTP id 5859F486E0;
	Mon, 20 Oct 2025 17:05:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 32B33C4CEF9;
	Mon, 20 Oct 2025 17:05:06 +0000 (UTC)
Received: from sofa.misterjones.org ([185.219.108.64] helo=goblin-girl.misterjones.org)
	by disco-boy.misterjones.org with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.98.2)
	(envelope-from <maz@kernel.org>)
	id 1vAtJf-0000000FaGq-3F9t;
	Mon, 20 Oct 2025 17:05:04 +0000
Date: Mon, 20 Oct 2025 18:05:03 +0100
Message-ID: <86ikg9wlkw.wl-maz@kernel.org>
From: "'Marc Zyngier' via kasan-dev" <kasan-dev@googlegroups.com>
To: Ada Couprie Diaz <ada.coupriediaz@arm.com>
Cc: linux-arm-kernel@lists.infradead.org,
	Catalin Marinas <catalin.marinas@arm.com>,
	Will Deacon <will@kernel.org>,
	Oliver Upton <oliver.upton@linux.dev>,
	Ard Biesheuvel <ardb@kernel.org>,
	Joey Gouly <joey.gouly@arm.com>,
	Suzuki K Poulose <suzuki.poulose@arm.com>,
	Zenghui Yu <yuzenghui@huawei.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Alexander Potapenko <glider@google.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	linux-kernel@vger.kernel.org,
	kvmarm@lists.linux.dev,
	kasan-dev@googlegroups.com,
	Mark Rutland <mark.rutland@arm.com>
Subject: Re: [RFC PATCH 12/16] kvm/arm64: make alternative callbacks safe
In-Reply-To: <20250923174903.76283-13-ada.coupriediaz@arm.com>
References: <20250923174903.76283-1-ada.coupriediaz@arm.com>
	<20250923174903.76283-13-ada.coupriediaz@arm.com>
User-Agent: Wanderlust/2.15.9 (Almost Unreal) SEMI-EPG/1.14.7 (Harue)
 FLIM-LB/1.14.9 (=?UTF-8?B?R29qxY0=?=) APEL-LB/10.8 EasyPG/1.0.0 Emacs/30.1
 (aarch64-unknown-linux-gnu) MULE/6.0 (HANACHIRUSATO)
MIME-Version: 1.0 (generated by SEMI-EPG 1.14.7 - "Harue")
Content-Type: text/plain; charset="UTF-8"
X-SA-Exim-Connect-IP: 185.219.108.64
X-SA-Exim-Rcpt-To: ada.coupriediaz@arm.com, linux-arm-kernel@lists.infradead.org, catalin.marinas@arm.com, will@kernel.org, oliver.upton@linux.dev, ardb@kernel.org, joey.gouly@arm.com, suzuki.poulose@arm.com, yuzenghui@huawei.com, ryabinin.a.a@gmail.com, glider@google.com, andreyknvl@gmail.com, dvyukov@google.com, vincenzo.frascino@arm.com, linux-kernel@vger.kernel.org, kvmarm@lists.linux.dev, kasan-dev@googlegroups.com, mark.rutland@arm.com
X-SA-Exim-Mail-From: maz@kernel.org
X-SA-Exim-Scanned: No (on disco-boy.misterjones.org); SAEximRunCond expanded to false
X-Original-Sender: maz@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=HlLf+uu1;       spf=pass
 (google.com: domain of maz@kernel.org designates 172.234.252.31 as permitted
 sender) smtp.mailfrom=maz@kernel.org;       dmarc=pass (p=QUARANTINE
 sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: Marc Zyngier <maz@kernel.org>
Reply-To: Marc Zyngier <maz@kernel.org>
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

nit: please keep $SUBJECT in keeping with the subsystem you are
patching: "KVM: arm64: Make alternative callbacks safe"

On Tue, 23 Sep 2025 18:48:59 +0100,
Ada Couprie Diaz <ada.coupriediaz@arm.com> wrote:
> 
> Alternative callback functions are regular functions, which means they
> or any function they call could get patched or instrumented
> by alternatives or other parts of the kernel.
> Given that applying alternatives does not guarantee a consistent state
> while patching, only once done, and handles cache maintenance manually,
> it could lead to nasty corruptions and execution of bogus code.
> 
> Make the KVM alternative callbacks safe by marking them `noinstr` and
> `__always_inline`'ing their helpers.
> This is possible thanks to previous commits making `aarch64_insn_...`
> functions used in the callbacks safe to inline.
> 
> `kvm_update_va_mask()` is already marked as `__init`, which has its own
> text section conflicting with the `noinstr` one.
> Instead, use `__no_instr_section(".noinstr.text")` to add
> all the function attributes added by `noinstr`, without the section
> conflict.
> This can be an issue, as kprobes seems to only block the text sections,
> not based on function attributes.
> 
> Signed-off-by: Ada Couprie Diaz <ada.coupriediaz@arm.com>
> ---
> This is missing `kvm_patch_vector_branch()`, which could receive the same
> treatment, but the `WARN_ON_ONCE` in the early-exit check would make it
> call into instrumentable code.
> I do not currently know if this `WARN` can safely be removed or if it
> has some importance.

This is only debug code, which could be easily removed. However, I'd
like to suggest that we add a method to indicate that a patching
callback has failed for whatever reason. This doesn't have to be a
complex piece of infrastructure, and can be best effort (you can only
fail a single callback in a single location).

But it would certainly help catching unexpected situations (been
there, done that, ended up with visible scars...).

> ---
>  arch/arm64/kvm/va_layout.c | 12 +++++++-----
>  1 file changed, 7 insertions(+), 5 deletions(-)
> 
> diff --git a/arch/arm64/kvm/va_layout.c b/arch/arm64/kvm/va_layout.c
> index 91b22a014610..3ebb7e0074f6 100644
> --- a/arch/arm64/kvm/va_layout.c
> +++ b/arch/arm64/kvm/va_layout.c
> @@ -109,7 +109,7 @@ __init void kvm_apply_hyp_relocations(void)
>  	}
>  }
>  
> -static u32 compute_instruction(int n, u32 rd, u32 rn)
> +static __always_inline u32 compute_instruction(int n, u32 rd, u32 rn)
>  {
>  	u32 insn = AARCH64_BREAK_FAULT;
>  
> @@ -151,6 +151,7 @@ static u32 compute_instruction(int n, u32 rd, u32 rn)
>  	return insn;
>  }
>  
> +__noinstr_section(".init.text")
>  void __init kvm_update_va_mask(struct alt_instr *alt,
>  			       __le32 *origptr, __le32 *updptr, int nr_inst)
>  {
> @@ -241,7 +242,8 @@ void kvm_patch_vector_branch(struct alt_instr *alt,
>  	*updptr++ = cpu_to_le32(insn);
>  }
>  
> -static void generate_mov_q(u64 val, __le32 *origptr, __le32 *updptr, int nr_inst)
> +static __always_inline void generate_mov_q(u64 val, __le32 *origptr,
> +				 __le32 *updptr, int nr_inst)
>  {
>  	u32 insn, oinsn, rd;
>

generate_mov_q() (and others) start with a BUG_ON(), which may not be
recoverable, just like WARN_ON() above. That's where we should be able
to fail (more or less) gracefully and at least indicate the failure.

Thanks,

	M.

-- 
Without deviation from the norm, progress is not possible.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/86ikg9wlkw.wl-maz%40kernel.org.
