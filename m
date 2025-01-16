Return-Path: <kasan-dev+bncBCLMXXWM5YBBB3N3UG6AMGQEEPUYQ7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3f.google.com (mail-qv1-xf3f.google.com [IPv6:2607:f8b0:4864:20::f3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 9169AA13092
	for <lists+kasan-dev@lfdr.de>; Thu, 16 Jan 2025 02:16:33 +0100 (CET)
Received: by mail-qv1-xf3f.google.com with SMTP id 6a1803df08f44-6d89154adabsf7679196d6.0
        for <lists+kasan-dev@lfdr.de>; Wed, 15 Jan 2025 17:16:33 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1736990190; cv=pass;
        d=google.com; s=arc-20240605;
        b=kIysuw+DdUHPeuDM1Tswqrmm/PB0vHG+zwYSe2xmsE1CUNHhjAbkWoow5VFP5h5ysC
         aU+/Vl4al3SdjstM8womzznkCBBTS4O0efNG4OQpOa02N6YL6UDy1ZcK0rVeDABdRUPq
         n0v7maWn0/KsnsNiqRP3rMMvZIziZ+Lksu/cVHobqmP0GAjxxuZCOR9XoDP18S/Y2O33
         RVm8FwMPywKizsgUMYRPx1gSVTiihvKPrSueM3IYwAb30pFurqPaGASNztoIL/mlURXS
         c9wF1Jo0kQYHZ6mCYE0bl82A1x9vTndluW1kuXYHuw4TIpjA3zP7n97ADCgBeaEA/4bq
         2zJg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=ClB0uoo0QvmAfpuO6ZaykdV/a/Iy3kxh+eozNEA8hOk=;
        fh=pHhGVlAdtu4okxI50q/wFk6i616kXi0ZD9Xsz61dtQI=;
        b=QVdwTyB+h2QYmZv8H0XKXVbbSvnZHcRuU3eDzu/CoDsSbYZhN3tzhMwV9ms6KXif+8
         Y/3fbFPrxukyzOiyixkY9Kp+wo+ejueAwQ8zxiNOl7trlP6wRIsqpbEtDfPYzwR3obus
         A7PIs1r1kT836SArZVP3qDW/n0a8RCkAn0c6AEBaZG1ZifKqMEkenA1C9eYkwwSwQcrP
         oqLdzygVGM7HUkPMCKSG0J66ymvAHngI1akdHPIdSTgFs9nq98bFeX5s2A6l3rGdYATQ
         nOUqBFZRVXQnPavZsv2tgaAcTypiAFSxJNlWmd3aUOKij4OvXUkxUSthGPs9guVvj5nZ
         +kow==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Oaa9viUd;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1736990190; x=1737594990; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ClB0uoo0QvmAfpuO6ZaykdV/a/Iy3kxh+eozNEA8hOk=;
        b=b8/slfCvYYoBNxrDYgta4ETgujR9MTGdVaz3oXYgP+PCnS2cViNJfHq+1THkKsc8zr
         zClnDHiPEQta+Qhbs3PhIsQ6phBxx91Up+3fsBD+649L6P0hZQEw/5K31kT4fqiIAVXA
         sdnHjsMFJLEXvz2+c4nv9x1Y2hvyCS9ERpPCZoGmp+K/ufGDpZOzhpWi7vSEoiI0bfQJ
         9Jo+vt9kHvI0BahwqEo3o6g8/qFonrqVbd8iECBZoqPY7/tGN7A4FjPKhTxB+YBZFGkk
         Vu+mnd3FYhYiISp2Mdngh5wUkT/3MookXuFNnhmth9sMRq6fJKGdeQKpM18nHgA1gAlC
         Hk7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1736990190; x=1737594990;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:x-beenthere
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ClB0uoo0QvmAfpuO6ZaykdV/a/Iy3kxh+eozNEA8hOk=;
        b=cEkqT0mpNgXH2ybO/NqBvHLPBgrjsLLS+m06xCR7dlSlHFiv2nte0NgAI/tS9eLybp
         xco2ZE0ikI0X5dR/N/DryuYIbACYWeYpdFIPYS9XY0fJVWlReKC5n2/y+MLa5jPRtp6B
         XiAaloXkzP5+T29YUPOw5TyfV+hfiss9WofpPWYehXq+qGDI97LJBIcaxYPASKD49sCK
         aRrHcgFlfEY4NAA2e0Q+WR7EU3O9/tUbbeu9D8w//HupEnXBcS2RtR5OdQreyDw0Zoy0
         7+DMceUEK5Bz0//hIq9b5d3p55Al4gVUBvKbwOEDa6x+SC5dzk3IP1eaSivJiRh2XoFn
         s25w==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCX7XqMm5Bd6B0f/lwH3UvRKuQoYezWdhxNPEPy54yAE5JlzUyx+XavGPnyovdAxRXYr8/1vAg==@lfdr.de
X-Gm-Message-State: AOJu0YzbTnrvFp7SMLr4oecyRcRmGZ4NpzmPzip8b/AmNxPAny2OgUli
	VUuyfcgyfkDt6yFoYBItDcw4lCi6psaBDthB0/WsKU+0/F9Ybwnx
X-Google-Smtp-Source: AGHT+IGN/9tWrj+WyobaeMxwebxPeE+vqijKDoZDpH+03hLv2bBgcvNxvN3P4N+USEhX4KdzfO5Cag==
X-Received: by 2002:a05:6214:570b:b0:6dc:d101:2bb2 with SMTP id 6a1803df08f44-6df9b0ee9b8mr528680556d6.0.1736990189668;
        Wed, 15 Jan 2025 17:16:29 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac8:6d08:0:b0:46b:cf11:757c with SMTP id d75a77b69052e-46e02ca116bls6089311cf.0.-pod-prod-09-us;
 Wed, 15 Jan 2025 17:16:28 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCV1YrtFEs7LmOQeK/Zi/s1dBOS6ejISfH2Cdfv3XAE8H3YIQa3z69qrOiD882PDkCQZvSjJrk9Kye4=@googlegroups.com
X-Received: by 2002:a05:620a:1714:b0:7b6:6701:7a4a with SMTP id af79cd13be357-7bcd9799d1emr5337063985a.53.1736990188771;
        Wed, 15 Jan 2025 17:16:28 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1736990188; cv=none;
        d=google.com; s=arc-20240605;
        b=X6PXRbJ+ISjw1v8agdeKAIWWC4h0Ef0B3RppIIb0EHPG8sZ1IE0XGfnjC7Jvnyosx0
         qvIW+wY1i4PrXZvEXmFMdx4bH9ge+4Urg1N9JLhj0MoUaeEY+iqIvcO8D36kuNI7khiV
         DqkA18aKPf2Pq122PGqzveeSH3QHRKJBIof142pspfSTyl4mpya2I1Jsxaz6+2UQO5kW
         086Hpqd7a6bLrpLQvel+Vg/fnp/Ie+qbGuvWZo5QPr8b+glwDtzfogGLix69D+nY5Fpt
         cpjzEdmK4r36sYOF+rQYdOqpNDN2LuvUmZNZreOCSJnIwZ+BBygLHP4hQK+sHLWgUix6
         t4Sg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-transfer-encoding:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date
         :dkim-signature;
        bh=cPr0S5mO7P+GKPipZ1nGtlwrnrd/h5OSZtw894A+hbo=;
        fh=2IybrTX/PJAXLrzhZfsAB0iHHoN2RyYyeA/I8YN0X90=;
        b=DOZubuHzzWxFPIxbYASLDS9AukfOwKabrMc1a5U3K/7Hs6oiuzWRjh800ZdNp+DsD1
         9AeumtELgWfTalK+LrszUorFsazQbXXsdDLoBV7+AicQON8nz60HzyAQbs+cALyq4zRB
         kfIL1zLkd1r9vkf5oW7ZjIfAnsuliLWCo7EFvQDV4+iQzcSe8FwwTkQ0CKcCc9DDsfMH
         SnzwGzxbk7ClPzQUH4bomjtg2b8G89RDv/SnJ6OW4nXL5xvpcCxQEqjawiqHfvrCyWhL
         0fdbVV6tmt/S6bG6vLQ0zy3s7WLt4fg7uxEHt93ZOM2S6gsLa8Gtrw6xtK1oBoOd53Wo
         JcJw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@quicinc.com header.s=qcppdkim1 header.b=Oaa9viUd;
       spf=pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
Received: from mx0b-0031df01.pphosted.com (mx0b-0031df01.pphosted.com. [205.220.180.131])
        by gmr-mx.google.com with ESMTPS id af79cd13be357-7bce32ffc17si55953085a.5.2025.01.15.17.16.28
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 15 Jan 2025 17:16:28 -0800 (PST)
Received-SPF: pass (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131 as permitted sender) client-ip=205.220.180.131;
Received: from pps.filterd (m0279872.ppops.net [127.0.0.1])
	by mx0a-0031df01.pphosted.com (8.18.1.2/8.18.1.2) with ESMTP id 50FGn6R4028621;
	Thu, 16 Jan 2025 01:16:24 GMT
Received: from nasanppmta02.qualcomm.com (i-global254.qualcomm.com [199.106.103.254])
	by mx0a-0031df01.pphosted.com (PPS) with ESMTPS id 446fgm17yb-1
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Jan 2025 01:16:24 +0000 (GMT)
Received: from nasanex01c.na.qualcomm.com (nasanex01c.na.qualcomm.com [10.45.79.139])
	by NASANPPMTA02.qualcomm.com (8.18.1.2/8.18.1.2) with ESMTPS id 50G1GNBM017104
	(version=TLSv1.2 cipher=ECDHE-RSA-AES256-GCM-SHA384 bits=256 verify=NOT);
	Thu, 16 Jan 2025 01:16:23 GMT
Received: from hu-jiangenj-sha.qualcomm.com (10.80.80.8) by
 nasanex01c.na.qualcomm.com (10.45.79.139) with Microsoft SMTP Server
 (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id
 15.2.1544.9; Wed, 15 Jan 2025 17:16:16 -0800
Date: Thu, 16 Jan 2025 06:46:13 +0530
From: Joey Jiao <quic_jiangenj@quicinc.com>
To: Alexander Potapenko <glider@google.com>
CC: Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
        "Andrey Konovalov" <andreyknvl@gmail.com>,
        Jonathan Corbet <corbet@lwn.net>,
        "Andrew Morton" <akpm@linux-foundation.org>,
        Dennis Zhou <dennis@kernel.org>, "Tejun Heo" <tj@kernel.org>,
        Christoph Lameter <cl@linux.com>,
        Catalin
 Marinas <catalin.marinas@arm.com>,
        Will Deacon <will@kernel.org>, <kasan-dev@googlegroups.com>,
        <linux-kernel@vger.kernel.org>, <workflows@vger.kernel.org>,
        <linux-doc@vger.kernel.org>, <linux-mm@kvack.org>,
        <linux-arm-kernel@lists.infradead.org>, <kernel@quicinc.com>
Subject: Re: [PATCH 0/7] kcov: Introduce New Unique PC|EDGE|CMP Modes
Message-ID: <Z4hd3bLA0178RxDi@hu-jiangenj-sha.qualcomm.com>
References: <20250114-kcov-v1-0-004294b931a2@quicinc.com>
 <CANpmjNPUFnxvY-dnEAv09-qB5d0LY_vmyxhb3ZPJV-T9V9Q6fg@mail.gmail.com>
 <Z4ZfzoqhrJA0jeQI@hu-jiangenj-sha.qualcomm.com>
 <CAG_fn=XFkNVkT3EmB99SdEBAwkGq3EUdM9xR4rzH_HatrJw8rQ@mail.gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <CAG_fn=XFkNVkT3EmB99SdEBAwkGq3EUdM9xR4rzH_HatrJw8rQ@mail.gmail.com>
X-Originating-IP: [10.80.80.8]
X-ClientProxiedBy: nasanex01b.na.qualcomm.com (10.46.141.250) To
 nasanex01c.na.qualcomm.com (10.45.79.139)
X-QCInternal: smtphost
X-Proofpoint-Virus-Version: vendor=nai engine=6200 definitions=5800 signatures=585085
X-Proofpoint-GUID: Z_olEk4WcSq3hsN4Oww5nUKM69KgZkLL
X-Proofpoint-ORIG-GUID: Z_olEk4WcSq3hsN4Oww5nUKM69KgZkLL
X-Proofpoint-Virus-Version: vendor=baseguard
 engine=ICAP:2.0.293,Aquarius:18.0.1057,Hydra:6.0.680,FMLib:17.12.68.34
 definitions=2025-01-15_11,2025-01-15_02,2024-11-22_01
X-Proofpoint-Spam-Details: rule=outbound_notspam policy=outbound score=0 lowpriorityscore=0
 malwarescore=0 impostorscore=0 mlxlogscore=536 bulkscore=0 suspectscore=0
 clxscore=1015 spamscore=0 adultscore=0 priorityscore=1501 phishscore=0
 mlxscore=0 classifier=spam adjust=0 reason=mlx scancount=1
 engine=8.19.0-2411120000 definitions=main-2501160007
X-Original-Sender: quic_jiangenj@quicinc.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@quicinc.com header.s=qcppdkim1 header.b=Oaa9viUd;       spf=pass
 (google.com: domain of quic_jiangenj@quicinc.com designates 205.220.180.131
 as permitted sender) smtp.mailfrom=quic_jiangenj@quicinc.com;
       dmarc=pass (p=NONE sp=REJECT dis=NONE) header.from=quicinc.com
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

On Wed, Jan 15, 2025 at 04:16:57PM +0100, Alexander Potapenko wrote:
> On Tue, Jan 14, 2025 at 2:00=E2=80=AFPM Joey Jiao <quic_jiangenj@quicinc.=
com> wrote:
> >
> > On Tue, Jan 14, 2025 at 11:43:08AM +0100, Marco Elver wrote:
> > > On Tue, 14 Jan 2025 at 06:35, Jiao, Joey <quic_jiangenj@quicinc.com> =
wrote:
> > > >
> > > > Hi,
> > > >
> > > > This patch series introduces new kcov unique modes:
> > > > `KCOV_TRACE_UNIQ_[PC|EDGE|CMP]`, which are used to collect unique P=
C, EDGE,
> > > > CMP information.
> > > >
> > > > Background
> > > > ----------
> > > >
> > > > In the current kcov implementation, when `__sanitizer_cov_trace_pc`=
 is hit,
> > > > the instruction pointer (IP) is stored sequentially in an area. Use=
rspace
> > > > programs then read this area to record covered PCs and calculate co=
vered
> > > > edges.  However, recent syzkaller runs show that many syscalls like=
ly have
> > > > `pos > t->kcov_size`, leading to kcov overflow. To address this iss=
ue, we
> > > > introduce new kcov unique modes.
>=20
> Hi Joey,
>=20
> Sorry for not responding earlier, I thought I'd come with a working
> proposal, but it is taking a while.
> You are right that kcov is prone to overflows, and we might be missing
> interesting coverage because of that.
>=20
> Recently we've been discussing the applicability of
> -fsanitize-coverage=3Dtrace-pc-guard to this problem, and it is almost
> working already.
Can you share the patch? I was tried trace-pc-guard but had the same unique=
=20
info problem.
> The idea is as follows:
> - -fsanitize-coverage=3Dtrace-pc-guard instruments basic blocks with
> calls to `__sanitizer_cov_trace_pc_guard(u32 *guard)`, each taking a
> unique 32-bit global in the __sancov_guards section;
> - these globals are zero-initialized, but upon the first call to
> __sanitizer_cov_trace_pc_guard() from each callsite, the corresponding
> global will receive a unique consequent number;
> - now we have a mapping of PCs into indices, which can we use to
> deduplicate the coverage:
> -- storing PCs by their index taken from *guard directly in the
> user-supplied buffer (which size will not exceed several megabytes in
> practice);
> -- using a per-task bitmap (at most hundreds of kilobytes) to mark
> visited basic blocks, and appending newly encountered PCs to the
> user-supplied buffer like it's done now.
Why at most hundreds of kilobytes? Still stored in sequence? Assume we have=
 2GB=20
kernel text, then bitmap will have 64MB for unique basic blocks?
>=20
> I think this approach is more promising than using hashmaps in kcov:
> - direct mapping should be way faster than a hashmap (and the overhead
> of index allocation is amortized, because they are persistent between
> program runs);
> - there cannot be collisions;
> - no additional complexity from pool allocations, RCU synchronization.
>=20
> The above approach will naturally break edge coverage, as there will
> be no notion of a program trace anymore.
I think guard value is equavalent to the effect of edge? We can use the gua=
rd=20
value in syzkaller as edge info?
> But it is still a question whether edges are helping the fuzzer, and
> correctly deduplicating them may not be worth the effort.
>=20
> If you don't object, I would like to finish prototyping coverage
> guards for kcov before proceeding with this review.
>=20
> Alex
Thanks Alex, sure, please continue the guards patches.
Also I think we can still store the covered PC inside=20
__santizer_cov_trace_pc_guard, right?

+void notrace __sanitizer_cov_trace_pc_guard(unsigned long* guard) {
+	struct task_struct *t;
+	struct kcov *kcov;
+	unsigned long ip =3D canonicalize_ip(_RET_IP_);
+
+	if (!*guard)
+		return;
>=20
> > > > 2. [P 2-3] Introduce `KCOV_TRACE_UNIQ_EDGE` Mode:
> > > >    - Save `prev_pc` to calculate edges with the current IP.
> > > >    - Add unique edges to the hashmap.
> > > >    - Use a lower 12-bit mask to make hash independent of module off=
sets.
>=20
> Note that on ARM64 this will be effectively using bits 11:2, so if I
> am understanding correctly more than a million coverage callbacks will
> be mapped into one of 1024 buckets.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z=
4hd3bLA0178RxDi%40hu-jiangenj-sha.qualcomm.com.
