Return-Path: <kasan-dev+bncBAABBJ5NZ6HQMGQE36WR2CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x939.google.com (mail-ua1-x939.google.com [IPv6:2607:f8b0:4864:20::939])
	by mail.lfdr.de (Postfix) with ESMTPS id 4FACD49F878
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:34 +0100 (CET)
Received: by mail-ua1-x939.google.com with SMTP id o12-20020ab0544c000000b002fa5ad28f16sf3109860uaa.18
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370152; cv=pass;
        d=google.com; s=arc-20160816;
        b=pfe9tJZ0+d8JsSV3ev+aHeET4zjn14GSS10wgWvbTtME1ORD2X+IWYrbQa1x6teyMn
         o6wxupzIqTPGPtyrPLp9YMaYLizwaA+cVeObSOR1EOaODhCLUUcafzyZ6CzhqWzj9twc
         r3X9I+osSxkvk9mglJMaGgNifav7UcnNlOshbIAKkE0gf5JPWkxiM5p78re95Cy1wiYI
         v+LM0lvCh3kHO66KBbuKGP+Hk2cl0HDR/9FjlMjDpuShWPis/gRYbamdj6zmvMDfp7gK
         FTh39YsjGY+269xuyBCuLcb2unWzW6B1mOAztmdMyiPQWNnwTdlvz9T0XrvOtCtWH5OD
         3TCg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=RZFEICCxBAsYI9CXCpD9RpMn+qGIlNEfCItorEgDGDY=;
        b=KhlRwPu6zd4fJzKWiFzzSMXVSc3f8dr8GLvteAEK9nfB+aoWlbUnBgRjC+yJz4m5Zt
         sL/QOVHfpKblEyvc5PfAEoB8FBC8zAbtR/VRyiePhVkfWuq7BYlQX0CcQUgfWudF79H7
         6Umu3Q8AjOPlcAyYFKt7weCWVaRE1J9iKj+VytxDgzPKWGESgL7GteapNRqpX3jtMcUe
         A9WiisfLstM2vWTTm1xkT6mizDNY4W7kGZja9olrcaxoLr4d8e0TwKb0gCPE/HpMao6w
         RdlE3dAec8jzanuhC82YHteLjee4Huy7niqCUxTDOAXOtaP2x1NBKXTB6PD+fI8F+ehq
         HlAQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZFEICCxBAsYI9CXCpD9RpMn+qGIlNEfCItorEgDGDY=;
        b=pbOS44moM/V2dY+RXV+/9wA5YZM4mkFDS13eVdHzgU8Jr0Taac+bnn3OL9xxFThuY/
         Il2YQpfoUCOZDxlEEgx4BYUsoBa/yBzAofo2WSxphuPPP0UmDo3eeDfpXy6OOIHTJ/Ns
         KH1R3rhi65eHZurLWhnacj2dOZcUtexHqfXI9Gb0VOIolSVfYae6m/2BoUzm7u0Hovzx
         uOMX+ihu+yDy3BrC6+rJTJZynLi+Im/3RGcQJyLJw/d6E/k2nKlmAgzOxgczpGp/d9Wm
         fxe+nX+vnMFvXnMmak2B20OUkMTf0hSKiJI6UgpnwPXkTyhuowHzeSz+6zk83ACoLCOS
         ZIHA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RZFEICCxBAsYI9CXCpD9RpMn+qGIlNEfCItorEgDGDY=;
        b=zF19KS+FJhBu8Gv7+svCMcTbIglP1ZS85ohW+yNnVuZSbTmmKb6eaPPdQQAmwNgNZ2
         nHB3YlQZLXL8lrjWUnsKqzxv8Pyz389tFIgnNYB9jIQM7MGNvfJc398S4ME0KR2ccLXh
         F2T+MkRONGcnqsVWrGZFhidA/csbo/kEvj8iTkYFRTkyrTx656e25s2ye3iITTz3g2FM
         sK6bgjKg7rthngktRH9RsXD0fGexGMJWReO9mVaz/NZ7PriP293dUegaRIw4WCP0Fvc5
         ggKyJH5xkRT9gBwbwyXCNU3OZ78t3k4bA9M7Mj2kzBeFn2RgZG/6qbUEixjTreQzV9P+
         7O6A==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531l9PUOkCllXs6dUTq3dBwh21nNMcE3ZOY7ZrjTZGc12ufDX2Mb
	PCZrxCDTPElgX8GPewSQqPE=
X-Google-Smtp-Source: ABdhPJwz3JTygIkhesCQURo0U+bJwimKujkF1KfbGBJCS6y6lywfwcLJbqTV3JmzyxzbrU9xacHnvg==
X-Received: by 2002:a05:6122:2024:: with SMTP id l36mr3782942vkd.16.1643370152181;
        Fri, 28 Jan 2022 03:42:32 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ab0:48c3:: with SMTP id y3ls795122uac.3.gmail; Fri, 28 Jan
 2022 03:42:31 -0800 (PST)
X-Received: by 2002:a9f:3727:: with SMTP id z36mr3623385uad.131.1643370151511;
        Fri, 28 Jan 2022 03:42:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370151; cv=none;
        d=google.com; s=arc-20160816;
        b=G0CMtcqxYknjRi4URSenksSfMkG6JQO8/jrm66pjBLUIYubV5FT1wlzkEPNagE17L1
         O/8nKUxC4szdV3SvIeUINGqZvXcbmFTAa/vlaf7vEyXKJVVTLBV0MVp+BLZedwZxRUL4
         bvFIvbfe7paVpFnJRm9u7vCJbF+T8CReklD89B1TKlw4Wb0Ohbn9oys1B1znHAgAFk68
         5IojL0ruYYiZ5TfURP/nT+dQCK7qSNY8KaAQFbKj+R+eG34LZX2jXTvDZbajKFU78va7
         usaS20s81CTb52ro9e3yN9vWu5ueKmRh3Xe7yHzxTyNlyNDZRbx5cRNZiobAscjRDeBt
         NxOA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=8ammFLQvGZyODjWsqpd1s1f5A13uP84NhZEWLvBCEGM=;
        b=aLCWRBKcFtAU5XOgycyN9S5QR/8QagYC14HbcnCaSlzzXDfdFW9YyNXOJxQ+mx551t
         48GDP+STJslVoIs0OukbWLT9n1pggGVy/ykbygR27L/ZmWhhmWN0oAOVuRft2s/e/8At
         yq6ACJjQ1GcbU6ms5KVhZhKSWMGXXIkryNuDOyPIt9CJCz+3428nAbv7rZz6yi5UAy49
         PqS0MeodkAFDmuDOzht94xjk5OLwOMgleD7ly+gGrnDg1y+TpjVNrJragPe6VknsiRnw
         qroKrtLJ04GJ2t4rc5eiOMbcyWjs6WlSh3RZBNr0hBCcwyyw5NvNnm/bB+xiztrpQJlL
         BP5g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id d5si435932uam.0.2022.01.28.03.42.30
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:31 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S7;
	Fri, 28 Jan 2022 19:42:28 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 5/5] kfence: unset panic_on_warn before calling panic()
Date: Fri, 28 Jan 2022 19:42:25 +0800
Message-Id: <1643370145-26831-6-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S7
X-Coremail-Antispam: 1UD129KBjvdXoW7Xw4kJF18Xr45GF1UXr1DZFb_yoWDGrX_C3
	40gw1kKw4kJa90ya1UKwn8Xr9rK3y2vr409Fs7WrZ0k34UGryjqF4rXF1kJ3yFgF4UCrW3
	tr1qqFyIkw4UCjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbgkYjsxI4VWkCwAYFVCjjxCrM7AC8VAFwI0_Wr0E3s1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l82xGYIkIc2x26280x7
	IE14v26r126s0DM28IrcIa0xkI8VCY1x0267AKxVW5JVCq3wA2ocxC64kIII0Yj41l84x0
	c7CEw4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r4j6ryUM28EF7xvwVC0I7IYx2
	IY6xkF7I0E14v26F4j6r4UJwA2z4x0Y4vEx4A2jsIE14v26rxl6s0DM28EF7xvwVC2z280
	aVCY1x0267AKxVW0oVCq3wAS0I0E0xvYzxvE52x082IY62kv0487Mc02F40EFcxC0VAKzV
	Aqx4xG6I80ewAv7VC0I7IYx2IY67AKxVWUJVWUGwAv7VC2z280aVAFwI0_Gr0_Cr1lOx8S
	6xCaFVCjc4AY6r1j6r4UM4x0Y48IcxkI7VAKI48JM4IIrI8v6xkF7I0E8cxan2IY04v7Mx
	kIecxEwVAFwVW8KwCF04k20xvY0x0EwIxGrwCFx2IqxVCFs4IE7xkEbVWUJVW8JwC20s02
	6c02F40E14v26r1j6r18MI8I3I0E7480Y4vE14v26r106r1rMI8E67AF67kF1VAFwI0_Jw
	0_GFylIxkGc2Ij64vIr41lIxAIcVC0I7IYx2IY67AKxVWUCVW8JwCI42IY6xIIjxv20xvE
	c7CjxVAFwI0_Cr0_Gr1UMIIF0xvE42xK8VAvwI8IcIk0rVWUJVWUCwCI42IY6I8E87Iv67
	AKxVW8JVWxJwCI42IY6I8E87Iv6xkF7I0E14v26r4j6r4UJbIYCTnIWIevJa73UjIFyTuY
	vjxUxVyxDUUUU
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
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

As done in the full WARN() handler, panic_on_warn needs to be cleared
before calling panic() to avoid recursive panics.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 mm/kfence/report.c | 10 +++++++++-
 1 file changed, 9 insertions(+), 1 deletion(-)

diff --git a/mm/kfence/report.c b/mm/kfence/report.c
index f93a7b2..9d61a23 100644
--- a/mm/kfence/report.c
+++ b/mm/kfence/report.c
@@ -267,8 +267,16 @@ void kfence_report_error(unsigned long address, bool is_write, struct pt_regs *r
 
 	lockdep_on();
 
-	if (panic_on_warn)
+	if (panic_on_warn) {
+		/*
+		 * This thread may hit another WARN() in the panic path.
+		 * Resetting this prevents additional WARN() from panicking the
+		 * system on this thread.  Other threads are blocked by the
+		 * panic_mutex in panic().
+		 */
+		panic_on_warn = 0;
 		panic("panic_on_warn set ...\n");
+	}
 
 	/* We encountered a memory safety error, taint the kernel! */
 	add_taint(TAINT_BAD_PAGE, LOCKDEP_STILL_OK);
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-6-git-send-email-yangtiezhu%40loongson.cn.
