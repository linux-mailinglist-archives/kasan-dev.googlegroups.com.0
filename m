Return-Path: <kasan-dev+bncBCM3NNW3WAKBBDXETHGQMGQE6BWRB4Q@googlegroups.com>
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail.lfdr.de
	by lfdr with LMTP
	id mOZ8LBBypmnePwAAu9opvQ
	(envelope-from <kasan-dev+bncBCM3NNW3WAKBBDXETHGQMGQE6BWRB4Q@googlegroups.com>)
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:56 +0100
X-Original-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x63e.google.com (mail-pl1-x63e.google.com [IPv6:2607:f8b0:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 57CD91E93F5
	for <lists+kasan-dev@lfdr.de>; Tue, 03 Mar 2026 06:30:56 +0100 (CET)
Received: by mail-pl1-x63e.google.com with SMTP id d9443c01a7336-2ae50463c39sf17778455ad.1
        for <lists+kasan-dev@lfdr.de>; Mon, 02 Mar 2026 21:30:56 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1772515855; cv=pass;
        d=google.com; s=arc-20240605;
        b=cLVMA+4sFlmC3eobM0deGm/aDKDclPui5+I0pXiuxZTDrWk8R3zP9gkDhnSsitwUUG
         5bLogmmUS40ViW7sEyq6BT9JRtJ1bWprICOoAZHIwsw6LLAou1y3Qx0m9ZdJwnQ4eDgP
         1LDEXZxKYGv+33mo2NIU/eV3yt0/h61uoBVV8m0U2F1xlQ3vM0gYR3yc/fgKP6FzIZTP
         VMCAT2HWE0MyK6M3ytiwBOwS1iJst/KoYEJ+X/rGCseqCkJ3HDC5hR6le3F/rpUVKN4v
         17kOAQ5nY+Axo2l1z/apxtOE2hZwJFOfCR5JLnTnnhfx99lsRpybdwYdYyZTnWvB0BIC
         0k6g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:in-reply-to:references
         :message-id:mime-version:subject:date:from:sender:dkim-signature;
        bh=fRnmWm/XARyFPQjfE5zE3ffaM64ha163maX2u1jt6Mc=;
        fh=8adQ2ga7uyZzyLpfqXCjzOIvS6gQXrgo5L7AZEBA8IY=;
        b=N/vrxO2cZeBHyhulZ/8KqUVjnAp2u+S+BnnD6IMAElcEiIFw6/Bsz4U3hqtGIoAHYJ
         QnqpB0f75Y8G4DB16SNmVPNqfDMDvUaw7qwdYEqsSPTsOVFoHbTBVkmWi9cH/Lk3fs3M
         vT3wPT8nyAMdnFcyQlwkK8LXw+6VYA9R3ijHYzQ1LP9irEMqPK2h84U/rfk47Wu3TZWj
         VkmBK8Ni/VNrjbiJvQiSLyYXzRA6PkyFxF+5sJHgVMQNDugC0mqJUUIh8L3mVJYdAINM
         5Wbw/Qx3chkQCDFhuDY3NA3iNckmF4umF08hv8oJ7XqUOx7iBOKBRK30bXzhP84FRTqW
         lA3A==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1772515855; x=1773120655; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:in-reply-to:references:message-id
         :mime-version:subject:date:from:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fRnmWm/XARyFPQjfE5zE3ffaM64ha163maX2u1jt6Mc=;
        b=BtKInb8JqeeOwQe2KnjmS2TAdhGoLsi35mmzcbH/ozyKLV8EYQd9rAtWvZCJJEbxZg
         h8G+C6JwwZwRfz17XjA/1Vd1Ps3C7WPCrWrLGqi/8PH9EHr0M3Y2BZbxAXTKf5bnjR3t
         mK8jzSMnNsY5KIjrPMiLjuTF7sUGxjrxK0WpqcLU9EgqXjSl05EEuDxvN9cP1acmXCz0
         snCsiz4S3qNnrv/4gCJ+pZlYu/PVrBLGGrzZfsZFVIvBwDGXRH+hGWI0N/kXxHJVdlSq
         qqGxasjCPZoaP1GFaFxXZWSUgaOQ9w4vxzVLxg6L8/lXiOcjgE+Veswd3D4bU6VDjD+6
         gNFw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1772515855; x=1773120655;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to
         :in-reply-to:references:message-id:mime-version:subject:date:from
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=fRnmWm/XARyFPQjfE5zE3ffaM64ha163maX2u1jt6Mc=;
        b=a+/Zt4Njqcxdmx8NbSsAYpKNtljSjaOb99EYfesNSnQ/6afTUTHFhQ0WY0lPKhXL0V
         j2iCm4ROnAIrm5RcyxJe+z3LdKusqfZL/0FzhqvEIXIU3DZnpoHdOwBiSVNwn2iCvRrj
         kCMC/f3t19k4vesAyQLPOBssmrecX6EhLJF4Jbq9rw57O6XhTjDKymzM3j6weDWCcy+M
         u3D+zknPEUESEni5npMyt4JbNPq+4TGtCUxVxUvOCSHw0dPgb2f6vjS2o6xbx6ByNElP
         az8PEjzxKueZ9MfqgPvmHHUg9eiYoFttjXwzcjcnsWMzRLG8v2AIV9hMLDUREoZxh8ot
         g4Og==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUC/COxebb7yiBuF0t92i2AVXSXrJZzaQ6dQJ/0SCqe1Yjd7ZS81rv04g4AmHgeJZZ4Yj+gXA==@lfdr.de
X-Gm-Message-State: AOJu0YymnnChxpnGb8zBF0+gdEx89qnZ5AOWTvunyIiDp1Kgn+PC5QDe
	urN8aa0kRxA1r4rHWrj96nXvbWbSoCu7ezKWdJswJugVURKDnedlxL3J
X-Received: by 2002:a17:903:32cc:b0:2ae:4555:479e with SMTP id d9443c01a7336-2ae45557aa1mr80981795ad.18.1772515854536;
        Mon, 02 Mar 2026 21:30:54 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="AV1CL+GK6P8qqKT8Ywf47mGTmC90kHFXAoA7iRNCXOldnDyLKA=="
Received: by 2002:a17:902:fa10:b0:2ae:5853:a9fb with SMTP id
 d9443c01a7336-2ae5853adccls9060765ad.1.-pod-prod-01-us; Mon, 02 Mar 2026
 21:30:53 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCXWB1kpbjC7z5wrW0HNxS8YkmgiZm3BUpVLKrz2ndAi+zHljYdjL+sPiujTxth6clg3MWoKvmVVrkE=@googlegroups.com
X-Received: by 2002:a17:903:2449:b0:2ae:57cc:63d7 with SMTP id d9443c01a7336-2ae57cc65femr31362625ad.7.1772515853115;
        Mon, 02 Mar 2026 21:30:53 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1772515853; cv=none;
        d=google.com; s=arc-20240605;
        b=eW8TCaOYdRYSISBibDnt9Epuh+wao6qENEgVaZtcHaw4Lq0MbOo/F96aeIV7cpZCYc
         il2cOIRl4RKDaqPxe5GQ9hcw37z+L8uTClaW0ITUGs6W+zOb7he+wOS8VnCxNd6aYGbB
         zIxqNu/INu+GX/CZncSa9dLTursXXZ96mV9FrCIMbqOh2BEek88nxtoMwp6dkem8sO9K
         +dgS1HYA7tHfg0g1Cq37GJu8+xXRev939PjrIZwTX2+QhuldaY/4cMJ/RYBaWtSTDpeC
         fwEyjL1DAIQsKMNjPdKvwF2VN8/q5FYOqjMMw13nFZa+lgTae4aaD+jA0VzcKkoWc6+T
         G4QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:in-reply-to:references:message-id:content-transfer-encoding
         :mime-version:subject:date:from;
        bh=VY6kxHrcg9uxKt3GR3N5nE6NzKM97xg7VvH9Q6ai9/Y=;
        fh=gT/s64yHh0Xs6H3zrWXXukiPDBj0+fd8/hEQlbq05js=;
        b=YuWfCBuwWY61z/HSMr0eANbGLULyN0oqp38eakzEINWSrEER8zMst0dtVKrLf5kACr
         baMjS7t5QEG3uXErWKnhOqiGKKjKHm7phNCJIEcor8XTJyjS/kfnXdjR6TWHVXJKXj3b
         q+7A0S9cD54DObK2X1zd50CYUR1ChBL/dW6GH+21CpOUmP5N3ktMKfqAV5yBDVfzl42P
         1bgnU4zO3rK3eBXTSJnLPCM1BUYx2shq73qT3rWcvS5yQpjIugPuFLE3GkN/SoBxIqWJ
         GbJJbe4gMUKmtO8psZ4D05qqJOyYAp4yEX1mg2veU4lJ39YQ+kcQlTqOmU/1S7T9YR/k
         NBZQ==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
Received: from cstnet.cn (smtp81.cstnet.cn. [159.226.251.81])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-2adfb6209c2si5475285ad.7.2026.03.02.21.30.52
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 02 Mar 2026 21:30:53 -0800 (PST)
Received-SPF: pass (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as permitted sender) client-ip=159.226.251.81;
Received: from [127.0.0.2] (unknown [210.73.43.101])
	by APP-03 (Coremail) with SMTP id rQCowAAHHdT9caZpAmO+CQ--.19798S7;
	Tue, 03 Mar 2026 13:30:39 +0800 (CST)
From: Vivian Wang <wangruikang@iscas.ac.cn>
Date: Tue, 03 Mar 2026 13:29:49 +0800
Subject: [PATCH v2 5/5] riscv: mm: Unconditionally sfence.vma for spurious
 fault
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Message-Id: <20260303-handle-kfence-protect-spurious-fault-v2-5-f80d8354d79d@iscas.ac.cn>
References: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
In-Reply-To: <20260303-handle-kfence-protect-spurious-fault-v2-0-f80d8354d79d@iscas.ac.cn>
To: Paul Walmsley <pjw@kernel.org>, Palmer Dabbelt <palmer@dabbelt.com>, 
 Alexandre Ghiti <alex@ghiti.fr>, Alexander Potapenko <glider@google.com>, 
 Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>, 
 Yunhui Cui <cuiyunhui@bytedance.com>
Cc: linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org, 
 kasan-dev@googlegroups.com, Palmer Dabbelt <palmer@rivosinc.com>, 
 stable@vger.kernel.org, Vivian Wang <wangruikang@iscas.ac.cn>
X-Mailer: b4 0.14.3
X-CM-TRANSID: rQCowAAHHdT9caZpAmO+CQ--.19798S7
X-Coremail-Antispam: 1UD129KBjvJXoW7tFWrtr4kWF45ZF15Jr17Awb_yoW8JFyrpw
	48GFs8Wr4rZr17Z3yfArn3u3WF93WkW3Z3Gan8u34fAw45Jr42qa1jvrW7KryIqFW0gr18
	AF4rA3sY9F1UArJanT9S1TB71UUUUU7qnTZGkaVYY2UrUUUUjbIjqfuFe4nvWSU5nxnvy2
	9KBjDU0xBIdaVrnRJUUUmI14x267AKxVWrJVCq3wAFc2x0x2IEx4CE42xK8VAvwI8IcIk0
	rVWrJVCq3wAFIxvE14AKwVWUJVWUGwA2048vs2IY020E87I2jVAFwI0_JF0E3s1l82xGYI
	kIc2x26xkF7I0E14v26ryj6s0DM28lY4IEw2IIxxk0rwA2F7IY1VAKz4vEj48ve4kI8wA2
	z4x0Y4vE2Ix0cI8IcVAFwI0_Xr0_Ar1l84ACjcxK6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr
	1UM28EF7xvwVC2z280aVAFwI0_Cr1j6rxdM28EF7xvwVC2z280aVCY1x0267AKxVW0oVCq
	3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzVAqx4xG6I80ewAv7VC0I7
	IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S6xCaFVCjc4AY6r1j6r4U
	M4x0Y48IcxkI7VAKI48JM4x0x7Aq67IIx4CEVc8vx2IErcIFxwACI402YVCY1x02628vn2
	kIc2xKxwCY1x0262kKe7AKxVWUtVW8ZwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkE
	bVWUJVW8JwC20s026c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67
	AF67kF1VAFwI0_Jw0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUCVW8JwCI
	42IY6xIIjxv20xvEc7CjxVAFwI0_Cr0_Gr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCw
	CI42IY6I8E87Iv67AKxVWUJVW8JwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnI
	WIevJa73UjIFyTuYvjfUeLvNUUUUU
X-Originating-IP: [210.73.43.101]
X-CM-SenderInfo: pzdqw2pxlnt03j6l2u1dvotugofq/
X-Original-Sender: wangruikang@iscas.ac.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of wangruikang@iscas.ac.cn designates 159.226.251.81 as
 permitted sender) smtp.mailfrom=wangruikang@iscas.ac.cn
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
X-Rspamd-Queue-Id: 57CD91E93F5
X-Rspamd-Server: lfdr
X-Spamd-Result: default: False [-1.71 / 15.00];
	ARC_ALLOW(-1.00)[google.com:s=arc-20240605:i=2];
	R_SPF_ALLOW(-0.20)[+ip6:2607:f8b0:4000::/36:c];
	R_DKIM_ALLOW(-0.20)[googlegroups.com:s=20230601];
	MAILLIST(-0.20)[googlegroups];
	MIME_GOOD(-0.10)[text/plain];
	HAS_LIST_UNSUB(-0.01)[];
	FROM_HAS_DN(0.00)[];
	RCVD_COUNT_THREE(0.00)[4];
	DMARC_NA(0.00)[iscas.ac.cn];
	SUSPICIOUS_AUTH_ORIGIN(0.00)[];
	FORGED_SENDER_MAILLIST(0.00)[];
	RCVD_TLS_LAST(0.00)[];
	RCPT_COUNT_TWELVE(0.00)[13];
	MIME_TRACE(0.00)[0:+];
	TAGGED_FROM(0.00)[bncBCM3NNW3WAKBBDXETHGQMGQE6BWRB4Q];
	FORGED_RECIPIENTS_MAILLIST(0.00)[];
	TO_DN_SOME(0.00)[];
	HAS_XOIP(0.00)[];
	FROM_NEQ_ENVFROM(0.00)[wangruikang@iscas.ac.cn,kasan-dev@googlegroups.com];
	DKIM_TRACE(0.00)[googlegroups.com:+];
	NEURAL_HAM(-0.00)[-1.000];
	TAGGED_RCPT(0.00)[kasan-dev];
	MID_RHS_MATCH_FROM(0.00)[];
	ASN(0.00)[asn:15169, ipnet:2607:f8b0::/32, country:US];
	DBL_BLOCKED_OPENRESOLVER(0.00)[googlegroups.com:dkim,googlegroups.com:email,iscas.ac.cn:mid,iscas.ac.cn:email,mail-pl1-x63e.google.com:rdns,mail-pl1-x63e.google.com:helo]
X-Rspamd-Action: no action

Svvptc does not guarantee that it's safe to just return here. Since we
have already cleared our bit, if, theoretically, the bounded timeframe
for the accessed page to become valid still hasn't happened after sret,
we could fault again and actually crash.

Hopefully, these spurious faults should be rare enough that this is an
acceptable slowdown.

Cc: <stable@vger.kernel.org>
Fixes: 503638e0babf ("riscv: Stop emitting preventive sfence.vma for new vmalloc mappings")
Signed-off-by: Vivian Wang <wangruikang@iscas.ac.cn>
---
 arch/riscv/kernel/entry.S | 7 +++++--
 1 file changed, 5 insertions(+), 2 deletions(-)

diff --git a/arch/riscv/kernel/entry.S b/arch/riscv/kernel/entry.S
index 9c6acfd09141..34717bd1fa91 100644
--- a/arch/riscv/kernel/entry.S
+++ b/arch/riscv/kernel/entry.S
@@ -75,8 +75,11 @@
 	/* Atomically reset the current cpu bit in new_valid_map_cpus */
 	amoxor.d	a0, a1, (a0)
 
-	/* Only emit a sfence.vma if the uarch caches invalid entries */
-	ALTERNATIVE("sfence.vma", "nop", 0, RISCV_ISA_EXT_SVVPTC, 1)
+	/*
+	 * A sfence.vma is required here. Even if we had Svvptc, there's no
+	 * guarantee that after returning we wouldn't just fault again.
+	 */
+	sfence.vma
 
 	REG_L	a0, TASK_TI_A0(tp)
 	REG_L	a1, TASK_TI_A1(tp)

-- 
2.53.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/20260303-handle-kfence-protect-spurious-fault-v2-5-f80d8354d79d%40iscas.ac.cn.
