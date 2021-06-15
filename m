Return-Path: <kasan-dev+bncBCP35GGZRMDRB5FQUODAMGQEUXKUFEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23f.google.com (mail-lj1-x23f.google.com [IPv6:2a00:1450:4864:20::23f])
	by mail.lfdr.de (Postfix) with ESMTPS id 870353A86B9
	for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 18:42:30 +0200 (CEST)
Received: by mail-lj1-x23f.google.com with SMTP id y10-20020a05651c154ab02901337d2c58f3sf6775119ljp.9
        for <lists+kasan-dev@lfdr.de>; Tue, 15 Jun 2021 09:42:30 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1623775350; cv=pass;
        d=google.com; s=arc-20160816;
        b=0o3L7YGyH9xLkPcUeRDCp0iSSyYwQZs4tzg5Q7Ql+fVwvO2KuqbZM55aEghnYQZ3q9
         xQecS3OTQQ5jqRt9jMWuI5qY/jHVKXV1Er7PPhpRVDIQPFv/Ru95OkXpK/Vw1+q1C7UL
         Q8eK/XgEWoEohq8nxG+wrk6N5Ix5VtXpAWWCg36O0zJrzmsHcTM546xRRVaIQYxFJp4D
         9HVVSzN2h7LLgHwiaAgPDXxpKCUmYUmfdfpLIueMyhrIAAErWiIteIL2zQ2e97v3iQGG
         OnR3mt2M2ev+Eh8NqO0kVDivuWEtC4JrNNe0mv4pQD+w5qaPA5LWtBihmbuoCaOB0jj/
         eCPw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature
         :dkim-signature;
        bh=dFAGFAbZFhQm+k1XJVsKh1ayWha2m+z1h7T5JcJxZbE=;
        b=itHgAMejApJ589Q6GXZAuHVoZi9EwHjfu41rvmN1NCSRN48QDXs+zHz7A9Sq0J8wpV
         dcF8B7welS0zww7m4es+rOT1bu40F3Ik+GwyPUiB4con6hDHxBjLVBFbXMDDhYELyaxs
         JJqbScy9SNRcDyzT+BxBSmAwea0AWuw3tfWJMPfmPRqQMR0aIaHKRD4QxxiqWj6qZWCy
         I3Y38M15IEjxJIzBCbt0056Aol3QdtS0+maa1xJcHEubvacPOiioJsEJMkN4O2VPXLj8
         X9x549NX+QyhT8kxA1JHsoj24FO8p48wvoDz/cBnagCIpBI9vZXwe/fhitYIj+Ogm+3f
         awWQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mybjY4le;
       spf=pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFAGFAbZFhQm+k1XJVsKh1ayWha2m+z1h7T5JcJxZbE=;
        b=IcMeQVhXjP6vsJAV0m7rCcj5eHZIJhI+BGJL+w/T/BvgvuP53t/b8dJxWtDDO8nrSU
         Y0WTC1ET68iVq5LIXRr5/esEyZFBwysbfQfxIBCfOzF4eECu6sjgW8DhNddncQ95EsDa
         VZxczQvRSnCHbObOgTuLjOLXE/crBGnJmqNImBxuHO4xYcmuLXMQWPizDdfOapwVwzlp
         U6hlcIQmF3HDgPGL6Oa+cbeH+zSxJyL7Wz1W7wNM0KuxQ09D4bse6BAuFpVzxI7tiKRp
         NOPsV0rcg6fpyfqxFOmfeeRqP1USpnFRLWp3lG0kSpsAowRwJZSXPsLht24lR0aDOCS1
         RCdA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFAGFAbZFhQm+k1XJVsKh1ayWha2m+z1h7T5JcJxZbE=;
        b=CgW1HyhAahSws4ZPUZiqPdKpJJ2Z38D1ANkBv4wKZKd3HySlFolInePLotgiF2pVpF
         ObVQVxO8/zsPkaTKtkW7R2A2UWo7ZgcFLqOw7BcnwuOc4Qj3Qv4g3BUvSaYHDZJ7mUJS
         5N0Q9+49+Aof6H1Zvze4lw3dc6QVu7iAHVLhot/pwAkxWzjpXOQa7VNE5TxJf1r8JWx4
         /7kyTdW71lIRqWy8FOvWLgQ4zS8woLKm7Pske/aC+ZCT34QwifXZDuZP/3SKpGVSlMeY
         B4kcZEW/7wENocjydnTV4r+yLmjVqzKekE/juYx8zoBX9vqEJoJ+Pbp327juy8gsd9ek
         mbnw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=dFAGFAbZFhQm+k1XJVsKh1ayWha2m+z1h7T5JcJxZbE=;
        b=tT4iHixSPzX13RIqaos+abGgBH559ED4GySNBDgZBNpDxIMUGMTSL8/Q3RB9J4LcHP
         9NeVIpmNjJuZJgZYA3JEES0yp3NdaNlFClt4bGmO1LG2JQEGg5mOnaemPzrtpv59uJKt
         vpQoGE0zfvYS2Z/G4G+kKLYhbLYtGw1tJPMsOzSYjwCkychs3nBTuZmmNWVmZRXUZSM2
         nSCuLch6fJo4y8tmxjLeGE87KwO2Zf6RcEasTZrFdC7ZGIq/rJzv0qWJ/0UGeeXdw8Od
         kFwHlbu13wxkMjdT+8tJezOF3GMCh7xZF1acLqZvtT82UQ/sRsGuW7yrVhAT4zZZZC2J
         GbqQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533ZTafTZDhi//TUICrPaBmfqiQDVYTOUPDFB1/0R2rShjc+E+WH
	cD5219BlJc/BuI2XzVWhMwo=
X-Google-Smtp-Source: ABdhPJw8m0zreg7lAFi8KNSF/WlZ//6se2lTauZ5p/xyKkRM750KcZ0H+8nRZcpwMS8vnnpqk1MAhg==
X-Received: by 2002:a2e:98d0:: with SMTP id s16mr440985ljj.155.1623775348669;
        Tue, 15 Jun 2021 09:42:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6512:3a86:: with SMTP id q6ls1026207lfu.3.gmail; Tue, 15
 Jun 2021 09:42:27 -0700 (PDT)
X-Received: by 2002:ac2:561a:: with SMTP id v26mr231970lfd.48.1623775347676;
        Tue, 15 Jun 2021 09:42:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1623775347; cv=none;
        d=google.com; s=arc-20160816;
        b=V5KeTUEx5RTluNU9sJ33N66WWbHC/V2sFg//kzMkGleHaCPvb1EKxGvAqVbsgCs8B4
         NXq2PUkobTOQgdYFbKPKlcIRHc0+sBNFJ6PMQ3IAJsvQgIkJdY+t0mi7ffl7Dt0mD4UH
         hM/9WEuiQdTTKNMLMqmgVDGeyr9rPWTp+tN7UvhhMFZh6Z6mDwoSuOEYXTLhNb5wbPFv
         1nNKRkmTQMYkYw7gbshjQHFmeHOhaZyl95VnOJEsuxpq2jwgT4X4BfPDLh/wdjkmssCf
         oaan/qdPpPRyQTIh/15EKpNWqMHOjhI47b0pxUBNfs5V5HqV1vILjxf+MqrAH8S22A4Y
         hd8Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:dkim-signature;
        bh=5HqZgwKlnzHk7eYEZtH1CaDCUYRbqEaAMkPzJHvXqS0=;
        b=KKYGUPCrNH4mz5uCO619nA4ZywoeHWJYltbRE2e7j+mDEckhoi6NOgvc187nnj+U26
         aHaSM7IjV1j04H+1GSbw8dLH83+run/0h7D+iFaF84MyjY0LXbLPhA+TV7mAYjfsJI7C
         qVn1AdEtJQyxjv8Jcad/ewvfRGgAL6q56IXbPfk2TpF1tIN9MCpFuj/2ZL6WHfj5b/Ex
         xtTGuppXrg5v2nAIwuRzQ2o3MQetOU/kQEeJ8CcBIQMdh6I4Vdqk082A07o3WauqVMUb
         42fjqRZrWdbKo7b97az1u5CjJDXXmgYb5AIPs5sHSQx1gUagk1C0EMIox/7+Sw6Eyxpq
         qqYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=mybjY4le;
       spf=pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-wr1-x432.google.com (mail-wr1-x432.google.com. [2a00:1450:4864:20::432])
        by gmr-mx.google.com with ESMTPS id q10si115014lfo.11.2021.06.15.09.42.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 15 Jun 2021 09:42:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of fuzzybritches0@gmail.com designates 2a00:1450:4864:20::432 as permitted sender) client-ip=2a00:1450:4864:20::432;
Received: by mail-wr1-x432.google.com with SMTP id c5so19033268wrq.9;
        Tue, 15 Jun 2021 09:42:27 -0700 (PDT)
X-Received: by 2002:a05:6000:110e:: with SMTP id z14mr26964792wrw.235.1623775347448;
        Tue, 15 Jun 2021 09:42:27 -0700 (PDT)
Received: from localhost.localdomain ([185.199.80.151])
        by smtp.gmail.com with ESMTPSA id t11sm7387549wrz.7.2021.06.15.09.42.25
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 15 Jun 2021 09:42:26 -0700 (PDT)
From: Kurt Manucredo <fuzzybritches0@gmail.com>
To: ebiggers@kernel.org,
	syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
Cc: Kurt Manucredo <fuzzybritches0@gmail.com>,
	keescook@chromium.org,
	yhs@fb.com,
	dvyukov@google.com,
	andrii@kernel.org,
	ast@kernel.org,
	bpf@vger.kernel.org,
	daniel@iogearbox.net,
	davem@davemloft.net,
	hawk@kernel.org,
	john.fastabend@gmail.com,
	kafai@fb.com,
	kpsingh@kernel.org,
	kuba@kernel.org,
	linux-kernel@vger.kernel.org,
	netdev@vger.kernel.org,
	songliubraving@fb.com,
	syzkaller-bugs@googlegroups.com,
	nathan@kernel.org,
	ndesaulniers@google.com,
	clang-built-linux@googlegroups.com,
	kernel-hardening@lists.openwall.com,
	kasan-dev@googlegroups.com
Subject: [PATCH v5] bpf: core: fix shift-out-of-bounds in ___bpf_prog_run
Date: Tue, 15 Jun 2021 16:42:10 +0000
Message-Id: <85536-177443-curtm@phaethon>
X-Mailer: git-send-email 2.30.2
In-Reply-To: <YMJvbGEz0xu9JU9D@gmail.com>
References: <87609-531187-curtm@phaethon> <6a392b66-6f26-4532-d25f-6b09770ce366@fb.com> <CAADnVQKexxZQw0yK_7rmFOdaYabaFpi2EmF6RGs5bXvFHtUQaA@mail.gmail.com> <CACT4Y+b=si6NCx=nRHKm_pziXnVMmLo-eSuRajsxmx5+Hy_ycg@mail.gmail.com> <202106091119.84A88B6FE7@keescook> <752cb1ad-a0b1-92b7-4c49-bbb42fdecdbe@fb.com> <CACT4Y+a592rxFmNgJgk2zwqBE8EqW1ey9SjF_-U3z6gt3Yc=oA@mail.gmail.com> <1aaa2408-94b9-a1e6-beff-7523b66fe73d@fb.com> <202106101002.DF8C7EF@keescook> <CAADnVQKMwKYgthoQV4RmGpZm9Hm-=wH3DoaNqs=UZRmJKefwGw@mail.gmail.com>
MIME-Version: 1.0
X-Original-Sender: fuzzybritches0@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=mybjY4le;       spf=pass
 (google.com: domain of fuzzybritches0@gmail.com designates
 2a00:1450:4864:20::432 as permitted sender) smtp.mailfrom=fuzzybritches0@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Content-Type: text/plain; charset="UTF-8"
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

Syzbot detects a shift-out-of-bounds in ___bpf_prog_run()
kernel/bpf/core.c:1414:2.

The shift-out-of-bounds happens when we have BPF_X. This means we have
to go the same way we go when we want to avoid a divide-by-zero. We do
it in do_misc_fixups().

When we have BPF_K we find divide-by-zero and shift-out-of-bounds guards
next each other in check_alu_op(). It seems only logical to me that the
same should be true for BPF_X in do_misc_fixups() since it is there where
I found the divide-by-zero guard. Or is there a reason I'm not aware of,
that dictates that the checks should be in adjust_scalar_min_max_vals(),
as they are now?

This patch was tested by syzbot.

Reported-and-tested-by: syzbot+bed360704c521841c85d@syzkaller.appspotmail.com
Signed-off-by: Kurt Manucredo <fuzzybritches0@gmail.com>
---

https://syzkaller.appspot.com/bug?id=edb51be4c9a320186328893287bb30d5eed09231

Changelog:
----------
v5 - Fix shift-out-of-bounds in do_misc_fixups().
v4 - Fix shift-out-of-bounds in adjust_scalar_min_max_vals.
     Fix commit message.
v3 - Make it clearer what the fix is for.
v2 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
     check in check_alu_op() in verifier.c.
v1 - Fix shift-out-of-bounds in ___bpf_prog_run() by adding boundary
     check in ___bpf_prog_run().

thanks

kind regards

Kurt

 kernel/bpf/verifier.c | 53 +++++++++++++++++++++++++------------------
 1 file changed, 31 insertions(+), 22 deletions(-)

diff --git a/kernel/bpf/verifier.c b/kernel/bpf/verifier.c
index 94ba5163d4c5..83c7c1ccaf26 100644
--- a/kernel/bpf/verifier.c
+++ b/kernel/bpf/verifier.c
@@ -7496,7 +7496,6 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 	u64 umin_val, umax_val;
 	s32 s32_min_val, s32_max_val;
 	u32 u32_min_val, u32_max_val;
-	u64 insn_bitness = (BPF_CLASS(insn->code) == BPF_ALU64) ? 64 : 32;
 	bool alu32 = (BPF_CLASS(insn->code) != BPF_ALU64);
 	int ret;
 
@@ -7592,39 +7591,18 @@ static int adjust_scalar_min_max_vals(struct bpf_verifier_env *env,
 		scalar_min_max_xor(dst_reg, &src_reg);
 		break;
 	case BPF_LSH:
-		if (umax_val >= insn_bitness) {
-			/* Shifts greater than 31 or 63 are undefined.
-			 * This includes shifts by a negative number.
-			 */
-			mark_reg_unknown(env, regs, insn->dst_reg);
-			break;
-		}
 		if (alu32)
 			scalar32_min_max_lsh(dst_reg, &src_reg);
 		else
 			scalar_min_max_lsh(dst_reg, &src_reg);
 		break;
 	case BPF_RSH:
-		if (umax_val >= insn_bitness) {
-			/* Shifts greater than 31 or 63 are undefined.
-			 * This includes shifts by a negative number.
-			 */
-			mark_reg_unknown(env, regs, insn->dst_reg);
-			break;
-		}
 		if (alu32)
 			scalar32_min_max_rsh(dst_reg, &src_reg);
 		else
 			scalar_min_max_rsh(dst_reg, &src_reg);
 		break;
 	case BPF_ARSH:
-		if (umax_val >= insn_bitness) {
-			/* Shifts greater than 31 or 63 are undefined.
-			 * This includes shifts by a negative number.
-			 */
-			mark_reg_unknown(env, regs, insn->dst_reg);
-			break;
-		}
 		if (alu32)
 			scalar32_min_max_arsh(dst_reg, &src_reg);
 		else
@@ -12353,6 +12331,37 @@ static int do_misc_fixups(struct bpf_verifier_env *env)
 			continue;
 		}
 
+		/* Make shift-out-of-bounds exceptions impossible. */
+		if (insn->code == (BPF_ALU64 | BPF_LSH | BPF_X) ||
+		    insn->code == (BPF_ALU64 | BPF_RSH | BPF_X) ||
+		    insn->code == (BPF_ALU64 | BPF_ARSH | BPF_X) ||
+		    insn->code == (BPF_ALU | BPF_LSH | BPF_X) ||
+		    insn->code == (BPF_ALU | BPF_RSH | BPF_X) ||
+		    insn->code == (BPF_ALU | BPF_ARSH | BPF_X)) {
+			bool is64 = BPF_CLASS(insn->code) == BPF_ALU64;
+			u8 insn_bitness = is64 ? 64 : 32;
+			struct bpf_insn chk_and_shift[] = {
+				/* [R,W]x shift >= 32||64 -> 0 */
+				BPF_RAW_INSN((is64 ? BPF_JMP : BPF_JMP32) |
+					     BPF_JLT | BPF_K, insn->src_reg,
+					     insn_bitness, 2, 0),
+				BPF_ALU32_REG(BPF_XOR, insn->dst_reg, insn->dst_reg),
+				BPF_JMP_IMM(BPF_JA, 0, 0, 1),
+				*insn,
+			};
+
+			cnt = ARRAY_SIZE(chk_and_shift);
+
+			new_prog = bpf_patch_insn_data(env, i + delta, chk_and_shift, cnt);
+			if (!new_prog)
+				return -ENOMEM;
+
+			delta    += cnt - 1;
+			env->prog = prog = new_prog;
+			insn      = new_prog->insnsi + i + delta;
+			continue;
+		}
+
 		/* Implement LD_ABS and LD_IND with a rewrite, if supported by the program type. */
 		if (BPF_CLASS(insn->code) == BPF_LD &&
 		    (BPF_MODE(insn->code) == BPF_ABS ||
-- 
2.30.2

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/85536-177443-curtm%40phaethon.
